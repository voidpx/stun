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
#include <ctype.h>
#include <sys/epoll.h>

#define SDEV "stun"
#define CDEV "ctun"

#define PORT 8888

#define AES_KEY_LEN 16
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define PACKET_MAX_LEN 1500

#define MAX_CONN 10
#define ID_LEN 4
#define IK_LEN (ID_LEN + AES_KEY_LEN)

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
#define pr_debug(...) do {printf("at %s:%d\n", __FILE__, __LINE__); printf(__VA_ARGS__);}while(0)
#define pr_debug_bin(...) _print(__VA_ARGS__)

#else
#define pr_debug(...)
#define pr_debug_iphdr(...)
#define pr_debug_bin(...)
#endif

#define _perror perror
#define perror(msg) do{printf("at %s:%d\n", __FILE__, __LINE__); _perror(msg);}while(0)

#define err_exit(msg) do {perror(msg); exit(1);} while(0)

enum Mode {
	SERVER,
	CLIENT
};

typedef struct hnod {
	struct hnod *next;
	void *key;
	void *data;
} hnod;

typedef struct htab {
	pthread_mutex_t lock;
	hnod **tab;
	size_t blen;
	size_t size;
	int (*hash)(void *);
	int (*equal)(void *, void*);
} htab;

typedef struct client {
	uint32_t id;
	uint32_t tun_ipv4;
	unsigned char *key;
	time_t heartbeat;
	struct sockaddr_in addr;
} client;

typedef struct ctx {
	int sofd;
	int tunfd;
	enum Mode mode;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX *enc_ctx;
	EVP_CIPHER_CTX *dec_ctx;
	char *tundev;

	// server: port to listen on, client: port of the server to connect to
	int port;
	union {
		// for client
		struct {
			char *vs;
			struct sockaddr_in server;
			uint32_t tip;

		};
		// for server
		struct {
			htab *conns; // lookup by address
			client *clients; // ip-to-client
		};
	};
	union {
		// client
		struct {
			unsigned char id[ID_LEN];
			unsigned char key[AES_KEY_LEN];
		};
		// server
		unsigned char keys[MAX_CONN * IK_LEN];
	};
	size_t tin, tout;
	pthread_t to_tun, from_tun;
	int epollfd;
	int down;
	unsigned char iv[GCM_IV_LEN];
	char gw[16];
	char mif[IFNAMSIZ + 1];
} ctx;

static int addr_hash(void *key) {
	struct sockaddr_in *a = (struct sockaddr_in *)key;
	return (int)(a->sin_addr.s_addr ^ a->sin_port);
}

static int addr_equal(void *k1, void *k2) {
	struct sockaddr_in *a1 = (struct sockaddr_in *)k1;
	struct sockaddr_in *a2 = (struct sockaddr_in *)k2;
	return a1->sin_addr.s_addr == a2->sin_addr.s_addr && a1->sin_port == a2->sin_port;
}

htab *htab_new(int buckets, int (*hash)(void*), int (*equal)(void*, void*)) {
	assert(buckets > 0);
	htab *h = malloc(sizeof(htab));
	if (!h) {
		return NULL;
	}
	int n = sizeof(hnod *) * buckets;
	h->tab = malloc(n);
	if (!h->tab) {
		free(h);
		return NULL;
	}
	memset(h->tab, 0, n);
	h->blen = buckets;
	h->hash = hash;
	h->equal = equal;
	h->size = 0;
	pthread_mutex_init(&h->lock, NULL);
	return h;
}

void htab_free(htab *h) {
	for (int i = 0; i < h->blen; ++i) {
		hnod *n = h->tab[i];
		while (n) {
			hnod *next = n->next;
			free(n);
			n = next;
		}
	}
	free(h->tab);
	free(h);
}

static hnod *hnod_new(void *key, void *value) {
	hnod *n = malloc(sizeof(hnod));
	if (!n) {
		return NULL;
	}
	n->key = key;
	n->data = value;
	n->next = NULL;
	return n;
}

void *htab_insert(htab *h, void *key, void *value) {
	int hash = h->hash(key);
	int i = ((size_t)hash) % h->blen;
	hnod **ref = &h->tab[i];
	void *ret = NULL;
	pthread_mutex_lock(&h->lock);
	while (*ref) {
		hnod *n = *ref;
		if (h->equal(key, n->key)) {
			void *p = n->data;
			n->data = value;
			ret = p;
			goto out;
		}
		ref = &n->next;
	}
	*ref = hnod_new(key, value);
	if (!*ref) {
		errno = ENOMEM;
		err_exit("OOM while inserting into hash table\n");
	}
	h->size++;
out:
	pthread_mutex_unlock(&h->lock);
	return ret;
}

void *htab_get(htab *h, void *key) {
	size_t hash = (size_t)h->hash(key);
	pthread_mutex_lock(&h->lock);
	hnod *n = h->tab[hash % h->blen];
	void *ret = NULL;
	while (n) {
		if (h->equal(key, n->key)) {
			ret = n->data;
			break;
		}
		n=n->next;
	}
	pthread_mutex_unlock(&h->lock);
	return ret;
}

void *htab_remove(htab *h, void *key) {
	size_t hash = (size_t)h->hash(key);
	hnod **ref = &h->tab[hash % h->blen];
	pthread_mutex_lock(&h->lock);
	hnod *n = *ref;
	void *ret = NULL;
	while (n) {
		if (h->equal(key, n->key)) {
			void *r = n->data;
			*ref = n->next;
			free(n);
			h->size--;
			ret = r;
			goto out;
		}
		ref = &n->next;
		n=*ref;
	}
out:
	pthread_mutex_unlock(&h->lock);
	return ret;
}

#define htab_foreach(h, n) \
	hnod *__next;\
	for (int i = 0; i < h->blen; ++i) \
		for (n = h->tab[i], __next=NULL; n && ((__next = n->next) || 1); n=__next)

static int stop;

#define _C_1(cond)\
	do {if (cond) return -1;} while (0)

static int enc(ctx *c, unsigned char* iv, unsigned char *key, unsigned char *msg, size_t len, unsigned char *out) {
	_C_1(1!=EVP_EncryptInit_ex(c->enc_ctx, c->cipher, NULL, NULL, NULL));
	_C_1(1!=EVP_CIPHER_CTX_ctrl(c->enc_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL));
	_C_1(1!=EVP_EncryptInit_ex(c->enc_ctx, NULL, NULL, key, iv));
	int outl;
	int tl = 0;
	_C_1(1!=EVP_EncryptUpdate(c->enc_ctx, out, &outl, msg, len));
	tl += outl;
	_C_1(1!=EVP_EncryptFinal_ex(c->enc_ctx, out+tl, &outl));
	tl += outl;
	_C_1(1!=EVP_CIPHER_CTX_ctrl(c->enc_ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out+tl));
    return 0;
}


static int dec(ctx *c, unsigned char* iv, unsigned char *key, unsigned char *emsg, size_t len, unsigned char *out) {
	_C_1(1 != EVP_DecryptInit_ex(c->dec_ctx, c->cipher, NULL, NULL, NULL));
	_C_1(1 != EVP_CIPHER_CTX_ctrl(c->dec_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL));
	_C_1(1 != EVP_DecryptInit_ex(c->dec_ctx, NULL, NULL, key, iv));
	int outl;
	_C_1(1 != EVP_DecryptUpdate(c->dec_ctx, out, &outl, emsg, len - GCM_TAG_LEN));
	int plaintext_len = outl;
	_C_1(1 != EVP_CIPHER_CTX_ctrl(c->dec_ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, emsg + len - GCM_TAG_LEN));
	_C_1(!EVP_DecryptFinal_ex(c->dec_ctx, out + plaintext_len, &outl));
	plaintext_len+=outl;
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
		char *ip = (char *)&c->tip;
		int err = exec_cmd("ip route add default via 10.0.0.%d dev %s metric 10", ip[3], dev);
		if (!reconfig) {
			_CMD(err);
		}
		exec_cmd("ip route add %s via %s dev %s", c->vs, c->gw, c->mif);
		// v6
		exec_cmd("ip -6 route add ::/0 dev %s metric 10", dev);
	}
}

static void enable_forwarding() {
	int fd = open("/proc/sys/net/ipv4/conf/all/forwarding", O_RDWR);
	if (fd < 0 || write(fd, "1", 1) != 1) {
		err_exit("error enabling ipv4 forwarding");
	}
	;
	close(fd);
	fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDWR);
	if (fd < 0 || write(fd, "1", 1) != 1) {
		err_exit("error enabling ipv6 forwarding");
	}
	close(fd);
}

static void setup_dev(ctx *c) {
	char *dev = c->tundev;
	_CMD(exec_cmd("ip link set dev %s up", dev));
	_CMD(exec_cmd("ip link set dev %s mtu %d", dev, MTU));
	_CMD(exec_cmd("ip link set dev %s multicast off", dev));
	if (c->mode == CLIENT) {
		int host = ((char *)&c->tip)[3];
		_CMD(exec_cmd("ip address add 10.0.0.%d/24 dev %s", host, dev));
		// v6
		_CMD(exec_cmd("ip -6 addr add fc00::%d/120 dev %s", host, dev));
	} else {
		enable_forwarding();
		_CMD(exec_cmd("ip address add 10.0.0.1/24 dev %s", dev));
		_CMD(exec_cmd("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24", c->mif));
		// v6
		_CMD(exec_cmd("ip -6 addr add fc00::1/120 dev %s", dev));
		_CMD(exec_cmd("ip6tables -t nat -A POSTROUTING -o %s -j MASQUERADE -s fc00::/120", c->mif));

	}
	setup_routes(c, 0);
}

static int bind_newsk(int port, in_addr_t a) {
	int so = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = a;
	addr.sin_port = htons(port);
	if (bind(so, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		err_exit("error bind");
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
		err_exit("error setting up tun device");
	}
	setup_dev(c);
	c->tunfd = fd;
}

static inline int check_ip(unsigned char *ip) {
	if (!(((ip[0] >> 4) & 15) ^ 0x4)) {
		struct iphdr *h = (struct iphdr*)ip;
		if (!IN_MULTICAST((uint32_t)ntohl(h->daddr))) {
			return 1;
		}
	} else if (!(((ip[0] >> 4) & 15) ^ 0x6)) {
		struct ipv6hdr *h = (struct ipv6hdr*)ip;
		if (!IN6_IS_ADDR_MULTICAST(&h->daddr)) {
			return 1;
		}
	}
	return 0;
}

static inline int ip_host(unsigned char *ip) {
	if (!(((ip[0] >> 4) & 15) ^ 0x4)) {
		struct iphdr *h = (struct iphdr*)ip;
		return ((char*)&h->daddr)[3];
	} else if (!(((ip[0] >> 4) & 15) ^ 0x6)) {
		struct ipv6hdr *h = (struct ipv6hdr*)ip;
		return ((char*)&h->daddr)[15];
	}
	return 0;
}

#define write_all(wfunc, fd, buf, len, ...) \
	({\
		int left = len; \
		unsigned char *b = buf; \
		do { \
			errno=0; \
			int w = wfunc(fd, b, left, ##__VA_ARGS__); \
			if (w == -1) { \
				perror("write error"); \
				break; \
			} \
			left -= w; \
			if (!left) { \
				break; \
			} \
			b+=w; \
			pr_debug("failed to write all at once, probably write queue is full\n"); \
			sched_yield(); \
		} while (1); \
		errno;\
	})


// server is .1, first client is .2, etc.
static inline int h2idx(int h) {
	return h-2;
}

static inline int idx2h(int i) {
	return i+2;
}

static inline int create_epollfd() {
	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		err_exit("error creating epollfd");
	}
	return epollfd;
}

static inline void epoll_add(int epollfd, int fd) {
	struct epoll_event ev = { 0 };
	ev.events = EPOLLIN;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		err_exit("error epoll add");
	}
}

static inline void epoll_del(int epollfd, int fd) {
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
		err_exit("error epoll add");
	}
}

static inline int _epoll_wait(int epollfd, int timeout) {
	struct epoll_event events[1];
	int nfds;
	if ((nfds = epoll_wait(epollfd, events, 1, timeout)) == -1) {
		perror("error epoll_wait");
	}
	return nfds;
}

static inline void set_nonblock(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		err_exit("error GETFL");
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		err_exit("error setting non-block");
	}
}

static inline void set_block(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		err_exit("error GETFL");
	}
	if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
		err_exit("error setting non-block");
	}
}

static void update_iv(ctx *c) {
	uint32_t r = rand();
	uint64_t *p = (uint64_t *)c->iv;
	*p = *p ^ (uint64_t)r;
	uint32_t *p2 = (uint32_t *)(c->iv + 8);
	*p2 = *p2 ^ r;
}

static int enc_and_send(ctx *c,  int so, unsigned char *key, unsigned char *buf, int len, struct sockaddr *addr, socklen_t sl) {
	assert(len <= PACKET_MAX_LEN - GCM_IV_LEN - GCM_TAG_LEN);
	unsigned char out[PACKET_MAX_LEN];
	memcpy(out, c->iv, sizeof(c->iv));
	if (enc(c, c->iv, key, buf, len, out + sizeof(c->iv)) < 0) {
		pr_debug("encryption error\n");
		return -1;
	}
	update_iv(c);
	int n = len + GCM_IV_LEN + GCM_TAG_LEN;
	c->tout+=n;
	return write_all(sendto, so, out, n, 0, addr, sl);
}

static uint32_t check_used_ip(ctx *c, unsigned char *id) {
	uint32_t iid = *(uint32_t *)id;
	for (int i = 0; i < MAX_CONN; ++i) {
		if (c->clients[i].id == iid) {
			htab_remove(c->conns, &c->clients[i].addr);
			return c->clients[i].tun_ipv4;
		}
	}
	return 0;
}

static inline void tun_fin(ctx *c, client *clt) {
	htab_remove(c->conns, &clt->addr);
	pr_debug("client disconnected: %x\n", clt->tun_ipv4);
	memset(clt, 0, sizeof(*clt));
}

static void tun_handshake(ctx *c, int so, struct sockaddr_in *remote, unsigned char *buf, int n) {
	if (n <= ID_LEN + GCM_IV_LEN + GCM_TAG_LEN) {
		pr_debug("invalid incoming connection\n");
		return;
	}
	for (int i = 0; i < MAX_CONN; ++i) {
		int ki = i * IK_LEN;
		unsigned char *kid = buf;
		if (!*(uint32_t *)kid) {
			continue;
		}
		if (!strncmp((char *)buf, (char *)&c->keys[ki], ID_LEN)) {
			unsigned char *iv = buf + ID_LEN;
			unsigned char *b = iv + GCM_IV_LEN;
			unsigned char *key = &c->keys[ki] + ID_LEN;
			int r = n - ID_LEN - GCM_IV_LEN;
			if (r == ID_LEN + GCM_TAG_LEN) { // new connection
				unsigned char id[ID_LEN];
				if (dec(c, iv, key, b, r, id)) {
					pr_debug("key mismatch\n");
					return;
				}
				if (strncmp((const char *)id, (const char *)kid, ID_LEN)) {
					pr_debug("id mismatch\n");
					return;
				}
				// allocate ip 10.0.0.0/24
				unsigned char ip[4] = {10, 0, 0, 0};
				uint32_t used = check_used_ip(c, kid);
				if (used) {
					ip[3] = ((char *)&used)[3];
				} else {
					for (int j = 0; j < MAX_CONN; ++j) {
						if (!c->clients[j].id) {
							ip[3] = (char)idx2h(j);
							goto ip_allocated;
						}
					}
					break;
				}
ip_allocated:
				int idx = h2idx(ip[3]);
				c->clients[idx].id=*(uint32_t *)kid;
				c->clients[idx].key = key;
				c->clients[idx].addr = *remote;
				c->clients[idx].tun_ipv4 = *(uint32_t *)ip;
				c->clients[idx].heartbeat = time(NULL);
				htab_insert(c->conns, &c->clients[idx].addr, &c->clients[idx]);
				pr_debug("client connected, id: %x, tip: %x, addr: %x, port: %x\n",
						c->clients[idx].id, c->clients[idx].tun_ipv4,
						remote->sin_addr.s_addr, remote->sin_port);
				if (enc_and_send(c, so, key, ip, sizeof(ip), (struct sockaddr *)remote, sizeof(*remote))) {
					pr_debug("error sending ip to client\n");
					tun_fin(c, &c->clients[idx]);
				}
				return;
				// established
			} else {
				pr_debug("invalid incoming connection packet\n");
			}
			return;
		}
	}
	pr_debug("invalid id\n");
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
		if (n == 0) {
			continue;
		}
		c->tin+=n;
		if (n < sizeof(c->iv) + GCM_TAG_LEN) {
			pr_debug("invalid packet\n");
			continue;
		}
		// server side connection handling before decryption
		unsigned char *key;
		client *clt;
		if (c->mode == SERVER) {
			clt = htab_get(c->conns, &ra);
			if (!clt) {
handshake:
				tun_handshake(c, sfd, &ra, buf, n);
				continue;
			}
			key = clt->key;
			clt->heartbeat = time(NULL);
		} else {
			key = c->key;
		}
		unsigned char *iv = buf;
		unsigned char *msg = buf + sizeof(c->iv);
		if (dec(c, iv, key, msg, n - sizeof(c->iv), dbuf) < 0) {
			pr_debug("decryption error\n");
			if (c->mode == SERVER) {
				// client reconnecting?
				pr_debug("client reconnecting\n");
				htab_remove(c->conns, &ra);
				memset(clt, 0, sizeof(*clt));
				goto handshake;
			}
			break;
		}
		// client quit
		if (c->mode == SERVER && !strncmp("QUIT", (const char *)dbuf, 4)) {
			tun_fin(c, clt);
			continue;
		}
		
		pr_debug("\nfrom tun decrypted===========================\n");
		pr_debug_iphdr(dbuf);
		pr_debug("\nfrom tun decrypted===========================end\n");
		
		int dlen = n - sizeof(c->iv) - GCM_TAG_LEN;
		if (write_all(write, c->tunfd, dbuf, dlen)) {
			if (c->mode == SERVER) {
				// probably client left
				tun_fin(c, clt);
			} else {
				// probably server down, exit
				pr_debug("error writing to tunnel device\n");
				break;
			}
		}
	}
	c->down = 1;
	return NULL;
}

static void *to_tun(void *hc) {
	ctx *c = (ctx *)hc;
	int fd = c->tunfd;
	int n;
	unsigned char buf[PACKET_MAX_LEN - sizeof(c->iv) - GCM_TAG_LEN];
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (!check_ip(buf)) {
			pr_debug("invalid or multicast ip packet, skipped\n");
			continue;
		}
		
		pr_debug("\nto tun===========================\n");
		pr_debug_iphdr(buf);
		pr_debug("\nto tun===========================end\n");
		
		unsigned char *key;
		struct sockaddr_in *to;
		if (c->mode == SERVER) {
			struct client *clt;
			int host = ip_host(buf);
			int i = h2idx(host);
			if (i < 0 || i >= MAX_CONN || !c->clients[i].id) {
				pr_debug("invalid host: %d, probably disconnected already\n", i);
				continue;
			}
			clt = &c->clients[i];
			key = clt->key;
			to = &clt->addr;
		} else {
			key = c->key;
			to = &c->server;
		}
		if (enc_and_send(c, c->sofd, key, buf, n, (struct sockaddr *)to, sizeof(*to))) {
			break;
		}
	}
	c->down = 1;
	return NULL;
}

static void start_forwarding(ctx *c) {
	c->down = 0;
	pthread_create(&c->to_tun, NULL, to_tun, c);
	pthread_create(&c->from_tun, NULL, from_tun, c);
}

// client connect protocol
static int _connect(ctx *c) {
	struct addrinfo ah = {0};
	ah.ai_family = AF_INET;
	ah.ai_socktype = SOCK_DGRAM;
	ah.ai_protocol = 0;
	struct addrinfo *ai;
	if (getaddrinfo(c->vs, NULL, &ah, &ai)) {
		err_exit("unable to resolve host");
	}
	int so = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = *(struct sockaddr_in*)ai->ai_addr;
	freeaddrinfo(ai);
	addr.sin_port = htons(c->port);
	c->server = addr;

	if (connect(so, (struct sockaddr *)&addr, sizeof(addr))) {
		goto err;
	}
	c->sofd = so;
	set_nonblock(so);
	int epollfd = create_epollfd();
	epoll_add(epollfd, so);

	unsigned char *id = c->id;
	int len = ID_LEN + ID_LEN + GCM_IV_LEN + GCM_TAG_LEN;
	unsigned char buf[64]; // reuse buf
	// 1 step, authenticate
	unsigned char *b = buf;
	memcpy(b, id, ID_LEN);
	b+= ID_LEN;
	memcpy(b, c->iv, sizeof(c->iv));
	b+=sizeof(c->iv);
	if (enc(c, c->iv, c->key, id, ID_LEN, b)) {
		err_exit("err encrypting\n");
	}
	for (int i = 0;; ++i) {
		pr_debug("connect %d\n", i);
		if (write_all(sendto, so, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr))) {
			goto err;
		}
		if (_epoll_wait(epollfd, (i+1) * 2 * 1000) > 0) {
			break;
		}
		if (i == 2) {
			pr_debug("unable to connect: peer not responding\n");
			goto err;
		}
	}
	struct sockaddr_in a;
	socklen_t slen = sizeof(a);
	unsigned char resp[GCM_IV_LEN + GCM_TAG_LEN + 4];
	int n = recvfrom(so, resp, sizeof(resp), 0, (struct sockaddr *)&a, &slen);
	if (n <= 0) {
		pr_debug("unable to connect\n");
		goto err;
	}
	assert(n == GCM_IV_LEN + GCM_TAG_LEN + 4);
	unsigned char dbuf[4];
	if (dec(c, resp, c->key, resp + GCM_IV_LEN, n - GCM_IV_LEN, dbuf)) {
		err_exit("error decrypting server response\n");
	}
	c->tip = *(uint32_t *)dbuf;

	update_iv(c);

	epoll_del(epollfd, so);
	close(epollfd);
	// connection established, switch to blocking mode
	set_block(so);
	setup_tun(c);

	start_forwarding(c);
	return 0;
err:
	return -1;
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
	"\t-P <control port> port for control\n"\
	"\n"

#define B64C "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static int b64(unsigned char *b, int len, char *out) {
	int i = 0;
	int o = 0;
	for (; i < len; i+=3) {
		out[o++] = B64C[b[i]>>2];
		out[o++] = B64C[((b[i]&3) << 4) | (i+1 < len ? (b[i+1] >> 4) : 0)];
		out[o++] = i+1 < len ? B64C[((b[i+1]&15) << 2) | (i+2 < len ? (b[i+2] >> 6) : 0)] : '=';
		out[o++] = i+2 < len ? B64C[(b[i+2]&63)] : '=';
	}
	return o;
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

static int rb64(unsigned char *b, int len, unsigned char *out) {
	assert(len % 4 == 0);
	int i = 0;
	int o = 0;
	for (; i+4 <= len; i+=4) {
		unsigned char c1 = bi(b[i]);
		unsigned char c2 = bi(b[i+1]);
		out[o++] = (c1 << 2) | (c2 >> 4);
		if (b[i+2] == '=') {
			break;
		}
		unsigned char c3 = bi(b[i+2]);
		out[o++] = ((c2 & 15) << 4) | (c3 >> 2);
		if (b[i+3] == '=') {
			break;
		}
		unsigned char c4 = bi(b[i+3]);
		out[o++] = ((c3 & 3) << 6) | c4;
	}
	return o;
}

static void genkey() {
	unsigned char rnd[ID_LEN + AES_KEY_LEN];
	getrandom(rnd, sizeof(rnd));
	char out[100];
	int n = b64(rnd, ID_LEN, out);
	out[n]='\0';
	printf("%s:", out);
	n = b64(rnd+ID_LEN, AES_KEY_LEN, out);
	out[n]='\0';
	printf("%s\n", out);
}

static void readkeys(char *keyfile, ctx *c) {
	unsigned char buf[100];
	FILE *fp = fopen(keyfile, "r");
	if (!fp) {
		err_exit("key file not found");
	}
	int m = c->mode == SERVER ? MAX_CONN : 1;
	for (int i=0; i < m; ++i) {
next:
		if (!fgets((char *)buf, sizeof(buf), fp)) {
			break;
		}
		unsigned char *p = buf;
		while (isspace(*p)) p++;
		if (!p[0]) {
			goto next;
		}

		unsigned char *k = (unsigned char *)strchr((char *)p, ':');
		if (!k) {
			err_exit("error reading key file\n");
		}
		int d = k - p;
		assert(d==8);
		assert(rb64(p, k-p, &c->keys[i*IK_LEN]) == ID_LEN);
		k++;
		int n = strlen((const char *)k);
		if (k[n-1] == '\r' || k[n-1] == '\n') {
			n--;
		}
		assert(rb64(k, n, &c->keys[i*IK_LEN + ID_LEN]) == AES_KEY_LEN);
	}
	fclose(fp);
}

static void cleanup(ctx *c) {
	pr_debug("cleanup\n");
	if (c->mode == SERVER) {
		exec_cmd("ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE -s fc00::/120", c->mif);
		exec_cmd("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24", c->mif);
		exec_cmd("ip route delete 10.0.0.0/24 dev %s", c->tundev);
		exec_cmd("ip -6 route delete fc00::/120 dev %s", c->tundev);
		htab_free(c->conns);
	} else {
		char *ip = (char *)&c->tip;
		exec_cmd("ip route delete %s via %s dev %s", c->vs, c->gw, c->mif);
		exec_cmd("ip route delete default via 10.0.0.%d metric 10", ip[3]);
		exec_cmd("ip -6 route delete ::/0 dev %s metric 10", c->tundev);
	}
}

static void reconnect(ctx *c) {
	pr_debug("reconnecting\n");
	pthread_cancel(c->to_tun);
	pthread_cancel(c->from_tun);
	pthread_join(c->to_tun, NULL);
	pthread_join(c->from_tun, NULL);
	close(c->tunfd);
	close(c->sofd);
	cleanup(c);

	// retrieve the default gw again
	get_def(c);
	_connect(c);
}

//static void cleanup_dead_conns(ctx *c) {
//	hnod *nod;
//	if (c->mode == SERVER) {
//		time_t now = time(NULL);
//		htab_foreach(c->conns, nod) {
//			struct sockaddr_in *sa = nod->key;
//			client *clt = nod->data;
//			if (now - clt->heartbeat > 10 * 60) { // 10 min
//				htab_remove(c->conns, sa);
//				pr_debug("remove dead connection: %x\n", clt->tun_ipv4);
//				memset(clt, 0, sizeof(*clt));
//			}
//		}
//	}
//}

static int _sendto(int so, char *buf, int len, struct sockaddr *addr, socklen_t sl) {
	int n;
	if ((n = sendto(so, buf, len, 0, addr, sl)) == -1) {
		perror("error sendto");
	}
	return n;
}

static void dump_conns(ctx *c, int so, struct sockaddr *addr, socklen_t sl) {
	hnod *nod;
	char buf[1024];
	char *b = buf;
	int len = 0;
	htab_foreach(c->conns, nod) {
		struct sockaddr_in *sa = nod->key;
		client *clt = nod->data;
		int s = snprintf(b, sizeof(buf) - len, "%x/%x\n", sa->sin_addr.s_addr, clt->tun_ipv4);
		b+=s;
		len+=s;
	}
	_sendto(so, buf, len, addr, sl);
}

static void wait_for_stop(ctx *c, int port) {
	int so = bind_newsk(port, htonl(INADDR_LOOPBACK));
	set_nonblock(so);
	int epollfd = create_epollfd();
	epoll_add(epollfd, so);
	int nfds;
	time_t lastreconn = time(NULL);
	while ((nfds = _epoll_wait(epollfd, 500)) != -1 || errno == EINTR) {
		if (stop) {
			break;
		}
		if (c->mode == CLIENT && c->down) {
			time_t now = time(NULL);
			if (now - lastreconn > 10) {
				pr_debug("connection was down, last reconnect: %ld, now: %ld, reconnect\n", lastreconn, now);
				reconnect(c);
				// reconnect fail
				lastreconn = time(NULL);
			}
		}/* else {
			cleanup_dead_conns(c);
		}*/
		if (nfds == 0) {
			continue;
		}
		int n;
		char buf[1024];
		struct sockaddr_in ra = {0};
		socklen_t ral = sizeof(ra);
		while ((n = recvfrom(so, buf, sizeof(buf), 0, (struct sockaddr *)&ra, &ral)) >= 0) {
			if (n >= 4 && !strncmp(buf, "stop", 4)) {
				pr_debug("stop received\n");
				goto out;
			} else if (c->mode == SERVER && n>=4 && !strncmp(buf, "list", 4)) {
				dump_conns(c, so, (struct sockaddr *)&ra, ral);
			} else if (!strncmp(buf, "stat", 4)) {
				int len = snprintf(buf, 100, "%ld/%ld\n", c->tin, c->tout);
				_sendto(so, buf, len, (struct sockaddr *)&ra, ral);
			}
		}
	}
out:
	close(epollfd);
	// stop
	if (c->mode == CLIENT && !c->down) {
		enc_and_send(c, c->sofd, c->key, (unsigned char *)"QUIT", 4, (struct sockaddr *)&c->server, sizeof(c->server));
	}
	close(c->sofd);
	close(c->tunfd);
}

static void init_crypto(char *keyfile, ctx *c) {
	readkeys(keyfile, c);
	getrandom(c->iv, sizeof(c->iv));
	srand(*(unsigned int *)c->iv);
	c->cipher = EVP_aes_128_gcm();
	if (!(c->enc_ctx = EVP_CIPHER_CTX_new())
			|| !(c->dec_ctx = EVP_CIPHER_CTX_new())) {
		pr_debug("error create cipher context\n");
		exit(1);
	}
}

static void uninit_crypto(ctx *c) {
	EVP_CIPHER_free((EVP_CIPHER *)c->cipher);
	EVP_CIPHER_CTX_free(c->enc_ctx);
	EVP_CIPHER_CTX_free(c->dec_ctx);
}

static void init_server_ctx(ctx *c) {
	c->conns = htab_new(MAX_CONN, addr_hash, addr_equal);
	int n = MAX_CONN * sizeof(client);
	c->clients = malloc(n);
	memset(c->clients, 0, n);
}


static inline void start_server(ctx *c) {
	c->sofd = bind_newsk(c->port, INADDR_ANY);
	setup_tun(c);
	start_forwarding(c);
}

int main(int argc, char **argv) {
	enum Mode m = SERVER;
	int port = PORT;
	char *server = NULL;
	char *mif = NULL;
	char *kf = NULL;
	char *gw = NULL;
	char *dev = NULL;
	int sport = 0;
	// poor man's arg parse
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-s") && i+1 < argc) {
			m = CLIENT;
			server = argv[i+1];
			i+=1;
		} else if (!strcmp(argv[i], "-p") && i+1 < argc) {
			port = atoi(argv[i+1]);
			i+=1;
		} else if (!strcmp(argv[i], "-P") && i+1 < argc) {
			sport = atoi(argv[i+1]);
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

	if (!sport) {
		sport = port + 1;
	}

	if (!kf) {
		kf = "tun.key";
	}

	ctx context = {0};
	context.mode = m;
	context.port = port;
	init_crypto(kf, &context);
	get_def(&context);

	if (mif) {
		strncpy(context.mif, mif, sizeof(context.mif) - 1);
	}
	if (m == SERVER) {
		context.tundev= dev ? dev : SDEV;
		init_server_ctx(&context);
		start_server(&context);

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
		if (_connect(&context)) {
			pr_debug("unable to connect");
			exit(1);
		}
	}
	setup_int();

	wait_for_stop(&context, sport);

	uninit_crypto(&context);
	cleanup(&context);
	return 0;
}

