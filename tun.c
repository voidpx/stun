#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <linux/ipv6.h>
#include <sched.h>
#include <arpa/inet.h>

#define SDEV "stun"
#define CDEV "ctun"

#define PORT 8888

#define AES_KEY_LEN 16
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define PACKET_MAX_LEN 1500

#define MTU (1500 - 20 - GCM_TAG_LEN - GCM_IV_LEN)

#ifdef DEBUG

static inline void _print(const unsigned char *s, int n) {
	while (n-- > 0) printf("%02x ", (unsigned char)*s++);
}

static void print_iphdr(const unsigned char *f) {
	if (!(((f[0] >> 4) & 15) ^ 0x4)) {
		struct iphdr *h = (struct iphdr *)f;
		printf("ipv4===========len: %d\nsrc: ", h->tot_len);
		_print((const unsigned char *)&h->saddr, sizeof(h->saddr));

		printf("\ndst: ");
		_print((const unsigned char *)&h->daddr, sizeof(h->daddr));
		printf("\nproto: %d", h->protocol);
		printf("\nipv4==========end\n");
	} else if (!(((f[0] >> 4) & 15) ^ 0x6)) {
		struct ipv6hdr *h = (struct ipv6hdr *)f;
		printf("ipv6===========payload len: %d\nsrc: ", h->payload_len);
		_print((const unsigned char *)&h->saddr, sizeof(h->saddr));

		printf("\ndst: ");
		_print((const unsigned char *)&h->daddr, sizeof(h->daddr));
		printf("\nnext header: %d", h->nexthdr);
		printf("\nipv6==========end\n");
	} else {
		printf("Not a ip packet\n");
	}
}
#define pr_debug_iphdr(...) print_iphdr(__VA_ARGS__)
#define pr_debug(...) printf(__VA_ARGS__)
#define pr_debug_bin(...) _print(__VA_ARGS__)

#else
#define pr_debug(...)
#define pr_debug_iphdr(...)
#define pr_debug_bin(...)
#endif

enum Mode {
	SERVER,
	CLIENT
};

typedef struct ctx {
	int sofd;
	int tunfd;
	enum Mode mode;
	char *vs;
	struct sockaddr_in peer;
	const EVP_CIPHER * cipher;
	char *tundev;
	unsigned char key[AES_KEY_LEN];
	unsigned char iv[GCM_IV_LEN];
	char gw[16];
	char mif[IFNAMSIZ + 1];
} ctx;

static int stop;

#define _C_1(cond)\
	do {if (cond) return -1;} while (0)

static int enc(ctx *c, unsigned char* iv, unsigned char *msg, size_t len, unsigned char *out) {
	EVP_CIPHER_CTX *ctx;
	_C_1(!(ctx = EVP_CIPHER_CTX_new()));
	_C_1(1!=EVP_EncryptInit_ex(ctx, c->cipher, NULL, NULL, NULL));
	_C_1(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL));
	_C_1(1!=EVP_EncryptInit_ex(ctx, NULL, NULL, c->key, iv));
	int outl;
	int tl = 0;
	_C_1(1!=EVP_EncryptUpdate(ctx, out, &outl, msg, len));
	tl += outl;
	_C_1(1!=EVP_EncryptFinal_ex(ctx, out+tl, &outl));
	tl += outl;
	_C_1(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out+tl));
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


static int dec(ctx *c, unsigned char* iv, unsigned char *emsg, size_t len, unsigned char *out) {
	EVP_CIPHER_CTX *ctx;
	_C_1(!(ctx = EVP_CIPHER_CTX_new()));
	_C_1(1 != EVP_DecryptInit_ex(ctx, c->cipher, NULL, NULL, NULL));
	_C_1(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL));
	_C_1(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, c->key, iv));
	int outl;
	_C_1(1 != EVP_DecryptUpdate(ctx, out, &outl, emsg, len - GCM_TAG_LEN));
	int plaintext_len = outl;
	_C_1(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, emsg + len - GCM_TAG_LEN));
	_C_1(!EVP_DecryptFinal_ex(ctx, out + plaintext_len, &outl));
	plaintext_len+=outl;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static int exec_cmd(char *fmt, ...) {
	char cmd[1024];
	va_list va;
	va_start(va, fmt);
	int n = vsnprintf(cmd, sizeof(cmd), fmt, va);
	va_end(va);
	if (n >= sizeof(cmd)) {
		fprintf(stderr, "command too long:\n");
		va_list va2;
		va_start(va2, fmt);
		vfprintf(stderr, fmt, va2);
		va_end(va2);
	}
	pr_debug("exeucting command: %s\n", cmd);
	return system(cmd);
}

void int_handler(int, siginfo_t *si, void *a) {
	pr_debug("interrupted\n");
	stop = 1;
}

static void setup_int() {
	struct sigaction sa = {0};
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = int_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		perror("sigaction: error setting up handler");
}

#define _CMD(call) \
	do {if ((call)) exit(1);} while(0)

static void setup_routes(ctx *c, int reconfig) {
	char *dev = c->tundev;
	if (c->mode == CLIENT) {
		int err = exec_cmd("ip route add default via 10.0.0.2 dev %s metric 10", dev);
		if (!reconfig) {
			_CMD(err);
		}
		exec_cmd("ip route add %s via %s dev %s", c->vs, c->gw, c->mif);
		// v6
		exec_cmd("ip -6 route add ::/0 dev %s metric 10", dev);
	} else {
		_CMD(exec_cmd("ip route add 10.0.0.0/24 dev %s", dev));
		// v6
		_CMD(exec_cmd("ip -6 route add fc00::/120 dev %s", dev));
	}

}

static void setup_dev(ctx *c) {
	char *dev = c->tundev;
	_CMD(exec_cmd("ip link set dev %s up", dev));
	_CMD(exec_cmd("ip link set dev %s mtu %d", dev, MTU));
	_CMD(exec_cmd("ip link set dev %s multicast off", dev));
	if (c->mode == CLIENT) {
		_CMD(exec_cmd("ip address add 10.0.0.2/32 dev %s", dev));
		// v6
		_CMD(exec_cmd("ip -6 addr add fc00::2/128 dev %s", dev));
	} else {
		_CMD(exec_cmd("ip address add 10.0.0.1/32 dev %s", dev));
		_CMD(exec_cmd("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24", c->mif));
		// v6
		_CMD(exec_cmd("ip -6 addr add fc00::1/128 dev %s", dev));
		_CMD(exec_cmd("ip6tables -t nat -A POSTROUTING -o %s -j MASQUERADE -s fc00::/120", c->mif));
	}
	setup_routes(c, 0);
	setup_int();
}

#define err_exit(msg) do {perror(msg); exit(1);} while(0)

static int start_server(int port) {
	int so = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(so, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err_exit("error binding");
	}
	return so;
}

static void get_def(ctx *c) {
	FILE *fp = fopen("/proc/net/route", "r");
	if (!fp) {
		err_exit("error opening /proc/net/route");
	}
	char line[100];
	while (fgets(line, 100, fp)) {
		char *p = strtok(line, " \t");
		char *n = strtok(NULL, " \t");
		if (p && n && !strcmp(n, "00000000")) {
			strncpy(c->mif, p, sizeof(c->mif) - 1);
			p = strtok(NULL, " \t");
			if (p) {
				unsigned int gw;
				struct in_addr addr;
				sscanf(p, "%x", &gw);
				addr.s_addr = gw;
				strncpy(c->gw, inet_ntoa(addr), sizeof(c->gw) - 1);
			}
			break;
		}
	}
	fclose(fp);
}

static void setup_tun(ctx* c) {
	int fd = open("/dev/net/tun", O_RDWR);
	struct ifreq req;
	memset(&req, 0, sizeof(req));
	req.ifr_flags = IFF_TUN | IFF_NO_PI;

	strcpy(req.ifr_name, c->tundev);

	int r = ioctl(fd, TUNSETIFF, &req);

	if (r < 0) {
		perror("error setting up tun device");
	}
	setup_dev(c);
	c->tunfd = fd;
}

static inline int check_mc(unsigned char *ip) {
	if (!(((ip[0] >> 4) & 15) ^ 0x4)) {
		struct iphdr *h = (struct iphdr*)ip;
		if (IN_MULTICAST((uint32_t)ntohl(h->daddr))) {
			return 1;
		}
	} else if (!(((ip[0] >> 4) & 15) ^ 0x6)) {
		struct ipv6hdr *h = (struct ipv6hdr*)ip;
		if (IN6_IS_ADDR_MULTICAST(&h->daddr)) {
			return 1;
		}
	} else {
		return 1;
	}
	return 0;
}

static int std_write(ctx *c, int fd, unsigned char *buf, int len) {
	return write(fd, buf, len);
}

static int _sendto(ctx *c, int fd, unsigned char *buf, int len) {
	return sendto(fd, buf, len, 0, (struct sockaddr *)&c->peer, sizeof(c->peer));
}

static int _write_all(ctx *c, int fd, unsigned char *buf, int len,
		int (*out)(ctx *c, int, unsigned char*, int)) {
	int left = len;
	unsigned char *b = buf;
	do {
		int w = out(c, fd, b, left);
		if (w == -1) {
			perror("write error");
			return errno;
		}
		left -= w;
		if (!left) {
			return 0;
		}
		b+=w;
		pr_debug("failed to write all at once to tunnel device, probably write queue is full\n");
		// busy loop yield
		sched_yield();
	} while (1);
}

static void *from_tun(void *hc) {
	ctx *c = (ctx *)hc;
	int sfd = c->sofd;
	int n;
	unsigned char buf[PACKET_MAX_LEN];
	unsigned char dbuf[PACKET_MAX_LEN];
	struct sockaddr_in ra = {0};
	socklen_t ral = sizeof(ra);
	while ((n = recvfrom(sfd, buf, sizeof(buf), 0, (struct sockaddr *)&ra, &ral)) >= 0) {
		if (stop) {
			break;
		}
		if (n == 0) {
			continue;
		}
		// decrypt
		if (n < sizeof(c->iv) + GCM_TAG_LEN) {
			pr_debug("invalid packet\n");
			continue;
		}
		unsigned char *iv = buf;
		unsigned char *msg = buf + sizeof(c->iv);
		if (dec(c, iv, msg, n - sizeof(c->iv), dbuf) < 0) {
			pr_debug("decryption error\n");
			continue;
		}
		int dlen = n - sizeof(c->iv) - GCM_TAG_LEN;
		pr_debug("\nfrom tun decrypted===========================\n");
		pr_debug_iphdr(dbuf);
		pr_debug("\nfrom tun decrypted===========================end\n");
		if (c->mode == SERVER) {
			pr_debug("\n peer:\n");
			pr_debug_bin((unsigned char*)&ra, ral);
			memcpy(&c->peer, &ra, sizeof(c->peer));
		}

		_write_all(c, c->tunfd, dbuf, dlen, std_write);
	}
	return NULL;
}

static void update_iv(ctx *c) {
	time_t t = time(NULL);
	long *p = (long *)c->iv;
	*p = *p ^ (long)t;
	int *p2 = (int *)(c->iv + 8);
	*p2 = *p2 ^ (int)t;
}

static void *to_tun(void *hc) {
	ctx *c = (ctx *)hc;
	int fd = c->tunfd;
	int n;
	int netdown = 0;
	unsigned char buf[PACKET_MAX_LEN - sizeof(c->iv) - GCM_TAG_LEN];
	unsigned char cbuf[PACKET_MAX_LEN];
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (stop) {
			break;
		}
		pr_debug("\nto tun===========================\n");
		pr_debug_iphdr(buf);
		if (check_mc(buf)) {
			pr_debug("multicast ip packet skipped\n");
			continue;
		}
		pr_debug("\nto tun===========================end\n");
		if (!c->peer.sin_addr.s_addr) {
			pr_debug("\nno peer yet, skip\n");
			continue;
		}
		memcpy(cbuf, c->iv, sizeof(c->iv));
		if (enc(c, c->iv, buf, n, cbuf + sizeof(c->iv)) < 0) {
			pr_debug("encryption error\n");
			continue;
		}
		int len = n + sizeof(c->iv) + GCM_TAG_LEN;

		int err = _write_all(c, c->sofd, cbuf, len, _sendto);
		if (err == ENETUNREACH) {
			netdown = 1; // network down
		} else if (!err && netdown) {
			// back online
			netdown = 0;
			pr_debug("network back online, reconfiguring routes\n");
			setup_routes(c, 1);
		}

		update_iv(c);
	}
	return NULL;
}

static int _connect(char *server, int port, ctx *c) {
	struct addrinfo ah = {0};
	ah.ai_family = AF_INET;
	ah.ai_socktype = SOCK_DGRAM;
	ah.ai_protocol = 0;
	struct addrinfo *ai;
	if (getaddrinfo(server, NULL, &ah, &ai)) {
		err_exit("unable to resolve host");
	}
	int so = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = *(struct sockaddr_in*)ai->ai_addr;
	freeaddrinfo(ai);
	addr.sin_port = htons(port);
	c->peer = addr;

	connect(so, (struct sockaddr *)&addr, sizeof(addr));
	c->sofd = so;
	return so;
}

static void getrandom(unsigned char *buf, int len) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		err_exit("error opening /dev/urandom");
	}
	if (read(fd, buf, len) < len) {
		err_exit("error reading from /dev/urandom");
	}
	close(fd);
}

#define USAGE \
	"A simple tunnel using pre-shared key for encryption\n\n"\
	"usage:\n"\
	"\t-s <vpn server> required for client mode\n"\
	"\t-p <port> optionl, the port to listen on in server mode, otherwise the server port to connect to, defualt is 8888\n"\
	"\t-i <interface> optional, the internet facing network interface\n"\
	"\t-k <key file> optional, the key file to use, see the -g option below, default is 'tun.key' in cwd\n"\
	"\t-g generate a key and ouput to stdout\n"\
	"\t-n <gateway> optional, the default next hop to route the connection to vpn server\n"\
	"\t-d <device name> optional device name\n"\
	"\n"

#define B64C "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static void b64(unsigned char *b, int len, char *out, int *outl) {
	int i = 0;
	int o = 0;
	for (; i < len; i+=3) {
		out[o++] = B64C[b[i]>>2];
		out[o++] = B64C[((b[i]&3) << 4) | (i+1 < len ? (b[i+1] >> 4) : 0)];
		out[o++] = i+1 < len ? B64C[((b[i+1]&15) << 2) | (i+2 < len ? (b[i+2] >> 6) : 0)] : '=';
		out[o++] = i+2 < len ? B64C[(b[i+2]&63)] : '=';
	}
	if (outl) {
		*outl = o;
	}
}

static inline unsigned char bi(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	} else if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	} else if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	} else if (c == '+') {
		return 62;
	} else if (c == '/') {
		return 63;
	}
	assert(0);
}

static void rb64(unsigned char *b, int len, unsigned char *out) {
	assert(len % 4 == 0);
	int i = 0;
	int o = 0;
	for (; i+4 <= len; i+=4) {
		unsigned char c1 = bi(b[i]);
		unsigned char c2 = bi(b[i+1]);
		unsigned char c3 = b[i+2] == '=' ? 0 : bi(b[i+2]);
		unsigned char c4 = b[i+3] == '=' ? 0 : bi(b[i+3]);
		out[o++] = (c1 << 2) | (c2 >> 4);
		out[o++] = ((c2 & 15) << 4) | (c3 >> 2);
		out[o++] = ((c3 & 3) << 6) | c4;
	}
}

static void genkey() {
	unsigned char key[AES_KEY_LEN];
	getrandom(key, sizeof(key));
	char out[30];
	int n;
	b64(key, AES_KEY_LEN, out, &n);
	out[n]='\0';
	printf("%s", out);

}

static void readkey(char *keyfile, ctx *c) {
	int fd = open(keyfile, O_RDONLY);
	char buf[30];
	int n;
	if (fd < 0 || (n = read(fd, buf, sizeof(buf))) <= 0) {
		err_exit("error reading key");
	}
	if (buf[n-1] == '\r' || buf[n-1] == '\n') {
		n--;
	}
	assert(n == 24);
	rb64((unsigned char *)buf, n, c->key);
	close(fd);
}

static void cleanup(ctx *c) {
	close(c->sofd);
	close(c->tunfd);
	pr_debug("cleanup\n");
	if (c->mode == SERVER) {
		exec_cmd("ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE -s fc00::/120", c->mif);
		exec_cmd("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24", c->mif);
		exec_cmd("ip route delete 10.0.0.0/24 dev %s", c->tundev);
		exec_cmd("ip -6 route delete fc00::/120 dev %s", c->tundev);
	} else {
		exec_cmd("ip route delete default via 10.0.0.2 metric 10");
		exec_cmd("ip -6 route delete ::/0 dev %s metric 10", c->tundev);
		exec_cmd("ip route delete %s via %s dev %s", c->vs, c->gw, c->mif);
	}
}

static void wait_for_stop(int port) {
	int so = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	if (bind(so, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err_exit("error binding at shutdown port");
	}
	int n;
	char buf[1024];
	struct sockaddr_in ra = {0};
	socklen_t ral = sizeof(ra);
	while ((n = recvfrom(so, buf, sizeof(buf), 0, (struct sockaddr *)&ra, &ral)) >= 0) {
		if (stop) {
			break;
		}
		if (!strncmp(buf, "stop", 4)) {
			pr_debug("stop received\n");
			stop = 1;
			break;
		}
	}
}

static void start_forwarding(ctx *c) {
	pthread_t totun, fromtun;
	pthread_create(&totun, NULL, to_tun, c);
	pthread_create(&fromtun, NULL, from_tun, c);
}

int main(int argc, char **argv) {
	enum Mode m = SERVER;
	int port = PORT;
	char *server = NULL;
	char *mif = NULL;
	char *kf = NULL;
	char *gw = NULL;
	char *dev = NULL;
	// poor man's arg parse
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-s") && i+1 < argc) {
			m = CLIENT;
			server = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-p") && i+1 < argc) {
			port = atoi(argv[i+1]);
			i+=1;
		} else if (!strcmp(argv[i], "-i") && i+1 < argc) {
			mif = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-h")) {
			printf("%s", USAGE);
			exit(0);
		} else if (!strcmp(argv[i], "-k") && i+1 < argc) {
			kf = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-g")) {
			genkey();
			exit(0);
		} else if (!strcmp(argv[i], "-n") && i+1 < argc) {
			gw = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-d") && i+1 < argc) {
			dev = argv[i+1];
			i+=1;
		}
	}

	if (!kf) {
		kf = "tun.key";
	}

	ctx context = {0};
	readkey(kf, &context);
	getrandom(context.iv, sizeof(context.iv));

	context.mode = m;
	context.cipher = EVP_aes_128_gcm();

	get_def(&context);

	if (mif) {
		strncpy(context.mif, mif, sizeof(context.mif) - 1);
	}
	if (m == SERVER) {
		context.tundev= dev ? dev : SDEV;
		setup_tun(&context);
		int sfd = start_server(port);
		context.sofd = sfd;
	} else {
		if (!server) {
			err_exit("VPN server must be provided with -s\n");
		}
		if (gw) {
			strncpy(context.gw, gw, sizeof(context.gw) - 1);
		}
		context.tundev= dev ? dev : CDEV;
		context.vs = server;
		// connect
		_connect(server, port, &context);
		setup_tun(&context);
	}

	start_forwarding(&context);

	wait_for_stop(port + 1);

	cleanup(&context);
	return 0;
}

