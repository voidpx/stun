/**
 * A simple VPN. client mode supports both Linux and macOS, server mode only
 * supports Linux.
 *
 */
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>

#if defined(__linux__)

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/limits.h>
#include <sys/epoll.h>

typedef struct iphdr iphdr;
typedef struct ipv6hdr ipv6hdr;

#define TUN_PKT_OFFSET 0

#elif defined(__MACH__)

// #include <netinet/ip.h>
// #include <netinet/ip6.h>
#include <Security/Security.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/route.h>
#include <sys/event.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>

#define TUN_PKT_OFFSET 4

typedef unsigned char __u8;
typedef unsigned short __be16;
typedef unsigned short __sum16;
typedef unsigned int __be32;
typedef struct iphdr {
  __u8 ihl : 4, version : 4;
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __sum16 check;
  __be32 saddr;
  __be32 daddr;
} iphdr;

typedef unsigned char in6_addr[16];
typedef struct ipv6hdr {
  __u8 priority : 4, version : 4;
  __u8 flow_lbl[3];

  __be16 payload_len;
  __u8 nexthdr;
  __u8 hop_limit;

  in6_addr saddr;
  in6_addr daddr;
} ipv6hdr;
#undef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) ((*a)[0] == (unsigned char)0xff)
#endif


#define SDEV "stun"
#define CDEV "ctun"

#define PORT 9527

#define AES_KEY_LEN 16
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define PACKET_MAX_LEN_C 1500
#define PACKET_MAX_LEN_S                                                       \
  ((65535 - 8 - 60) & ~0x7) // max ipv4 len - udp header - max ipv4 header

#define MAX_CONN 10
#define ID_LEN 4
#define ID_SESSION_LEN 4
#define IK_LEN (ID_LEN + AES_KEY_LEN)

// protocol header: 1 byte version, 1 byte op code, 4 byte key/session id
#define PROTO_VERSION 0x01 // 0.1
#define PROTO_HDR_LEN 6
// client-->server
#define PROTO_OP_CONNECT 'C' // connect
#define PROTO_OP_FORWARD 'F' // forward
#define PROTO_OP_FIN 'Q'     // quit

#define MTU                                                                    \
  (1500 - 20 - GCM_TAG_LEN - GCM_IV_LEN - 8) // max without fragmentation

#define LOG_FILE "/var/log/tun.log"

#define LOG_MAX_SIZE (1 << 14)

static char __attribute__((unused)) * get_time(char (*buf)[64]) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  time_t t = (time_t)ts.tv_sec;
  struct tm *tp = localtime(&t);
  char buffer[32];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tp);
  snprintf((char *)buf, sizeof(*buf), "%s.%.3ld", buffer, ts.tv_nsec / 1000000);
  return (char *)buf;
}

#ifdef DEBUG

static inline void _print(const unsigned char *s, int n) {
  while (n-- > 0)
    printf("%02x ", (unsigned char)*s++);
}

static void print_iphdr(const unsigned char *f) {
  if (!(((f[0] >> 4) & 15) ^ 0x4)) {
    iphdr *h = (iphdr *)f;
    printf("ipv4===========len: %d\nsrc: ", h->tot_len);
    _print((const unsigned char *)&h->saddr, sizeof(h->saddr));

    printf("\ndst: ");
    _print((const unsigned char *)&h->daddr, sizeof(h->daddr));
    printf("\nproto: %d", h->protocol);
    printf("\nipv4==========end\n");
  } else if (!(((f[0] >> 4) & 15) ^ 0x6)) {
    ipv6hdr *h = (ipv6hdr *)f;
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

static void print_time() {
  char buffer[64];
  get_time(&buffer);
  printf("%s ", buffer);
}

static pthread_mutex_t debug_lock;

static void debug_init() { pthread_mutex_init(&debug_lock, NULL); }

#define pr_debug_iphdr(...)                                                    \
  do {                                                                         \
    pthread_mutex_lock(&debug_lock);                                           \
    print_iphdr(__VA_ARGS__);                                                  \
    pthread_mutex_unlock(&debug_lock);                                         \
  } while (0)
#define pr_debug(...)                                                          \
  do {                                                                         \
    pthread_mutex_lock(&debug_lock);                                           \
    print_time();                                                              \
    printf("at %s:%d in %s():", __FILE__, __LINE__, __func__);                 \
    printf(__VA_ARGS__);                                                       \
    pthread_mutex_unlock(&debug_lock);                                         \
  } while (0)

#else
#define pr_debug(...)
#define pr_debug_iphdr(...)
#define debug_init()
#endif

#define _perror perror
#define perror(msg)                                                            \
  do {                                                                         \
    printf("at %s:%d\n", __FILE__, __LINE__);                                  \
    _perror(msg);                                                              \
  } while (0)

#define err_exit(msg)                                                          \
  do {                                                                         \
    perror(msg);                                                               \
    exit(1);                                                                   \
  } while (0)

enum Mode { SERVER, CLIENT };

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
  int (*equal)(void *, void *);
} htab;

typedef struct client {
  uint32_t id;
  uint32_t sessionid;
  uint32_t tun_ipv4;
  unsigned char *key;
  time_t heartbeat;
  pthread_mutex_t lock; // protect the addr
  struct sockaddr_in addr;
} client;

typedef struct ctx {
  int sofd;
  int tunfd;
  enum Mode mode;
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *enc_ctx;
  EVP_CIPHER_CTX *dec_ctx;
  char *tundev;
  uint32_t sessionid;
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
      htab *conns;     // lookup by session id
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
#ifdef __MACH__
  char gw6[80];
#endif
  char mif[IFNAMSIZ];
  unsigned char *recv_buf;
  unsigned char *send_buf;
  unsigned char *enc_buf;
  unsigned char *dec_buf;
  int recv_buf_len;
  int send_buf_len;
  int enc_buf_len;
  int dec_buf_len;
} ctx;

static int session_hash(void *key) {
  uint32_t k = (uint32_t)key;
  return k;
}

static int session_equal(void *k1, void *k2) {
  return (uint32_t)k1 == (uint32_t)k2;
}

htab *htab_new(int buckets, int (*hash)(void *), int (*equal)(void *, void *)) {
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
    n = n->next;
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
    n = *ref;
  }
out:
  pthread_mutex_unlock(&h->lock);
  return ret;
}

#define htab_foreach(h, n)                                                     \
  hnod *__next;                                                                \
  for (int i = 0; i < h->blen; ++i)                                            \
    for (n = h->tab[i], __next = NULL; n && ((__next = n->next) || 1);         \
         n = __next)

static pthread_mutex_t log_lock;
static FILE *logfile;

static inline void log_init() {
  pthread_mutex_init(&log_lock, NULL);
#ifdef ENABLE_LOG
  logfile = fopen(LOG_FILE, "a+");
  if (!logfile) {
    err_exit("error opening log file: " LOG_FILE);
  }
#else
  logfile = stdout;
#endif
}
static inline void log_uninit() {
#ifdef ENABLE_LOG
  fclose(logfile);
#endif
}

static void log_rotate() {
#ifdef ENABLE_LOG
  struct stat st;
  if (!stat(LOG_FILE, &st) && st.st_size > LOG_MAX_SIZE) {
    fclose(logfile);
    FILE *fp = fopen(LOG_FILE, "r");
    char *buf = malloc(st.st_size);
    if (!buf) {
      err_exit("out of memory");
    }
    int n = fread(buf, 1, st.st_size, fp);
    if (n < st.st_size) {
      err_exit("failed to read all content of the log file: " LOG_FILE);
    }
    int i = 0;
    while ((n - i) >= LOG_MAX_SIZE) {
      while (i < st.st_size && buf[i++] != '\n')
        ;
    }
    fclose(fp);

    if (i < st.st_size) {
      fp = fopen(LOG_FILE, "w");
      fwrite(buf + i, 1, (n - i), fp);
      fclose(fp);
    }
    free(buf);
    logfile = fopen(LOG_FILE, "a+");
  }
#endif
}

static void _log(char *template, ...) {
  pthread_mutex_lock(&log_lock);
  log_rotate();
  char buf[64];
  get_time(&buf);
  fprintf(logfile, "%s ", buf);
  va_list va;
  va_start(va, template);
  vfprintf(logfile, template, va);
  va_end(va);
  fprintf(logfile, "\n");
  fflush(logfile);
  pthread_mutex_unlock(&log_lock);
}

static int stop;
static int off;

#define _C_1(cond)                                                             \
  do {                                                                         \
    if (cond)                                                                  \
      return -1;                                                               \
  } while (0)

static int enc(ctx *c, unsigned char *iv, unsigned char *key,
               unsigned char *msg, size_t len, unsigned char *out) {
  _C_1(1 != EVP_EncryptInit_ex(c->enc_ctx, c->cipher, NULL, NULL, NULL));
  _C_1(1 != EVP_CIPHER_CTX_ctrl(c->enc_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN,
                                NULL));
  _C_1(1 != EVP_EncryptInit_ex(c->enc_ctx, NULL, NULL, key, iv));
  int outl;
  int tl = 0;
  _C_1(1 != EVP_EncryptUpdate(c->enc_ctx, out, &outl, msg, len));
  tl += outl;
  _C_1(1 != EVP_EncryptFinal_ex(c->enc_ctx, out + tl, &outl));
  tl += outl;
  _C_1(1 != EVP_CIPHER_CTX_ctrl(c->enc_ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                                out + tl));
  return 0;
}

static int dec(ctx *c, unsigned char *iv, unsigned char *key,
               unsigned char *emsg, size_t len, unsigned char *out) {
  _C_1(1 != EVP_DecryptInit_ex(c->dec_ctx, c->cipher, NULL, NULL, NULL));
  _C_1(1 != EVP_CIPHER_CTX_ctrl(c->dec_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN,
                                NULL));
  _C_1(1 != EVP_DecryptInit_ex(c->dec_ctx, NULL, NULL, key, iv));
  int outl;
  _C_1(1 != EVP_DecryptUpdate(c->dec_ctx, out, &outl, emsg, len - GCM_TAG_LEN));
  int plaintext_len = outl;
  _C_1(1 != EVP_CIPHER_CTX_ctrl(c->dec_ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                emsg + len - GCM_TAG_LEN));
  _C_1(!EVP_DecryptFinal_ex(c->dec_ctx, out + plaintext_len, &outl));
  plaintext_len += outl;
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
  _log("exeucting command: %s", cmd);
  return system(cmd);
}

void int_handler(int sig, siginfo_t *si, void *a) {
  _log("interrupted");
  stop = 1;
}

static void setup_int() {
  struct sigaction sa = {0};
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = int_handler;
  if (sigaction(SIGINT, &sa, NULL) == -1)
    perror("sigaction: error setting up handler");
}

#define _CMD(call)                                                             \
  do {                                                                         \
    if ((call))                                                                \
      exit(1);                                                                 \
  } while (0)

static void setup_routes(ctx *c, int reconfig) {
  char *dev = c->tundev;
  if (c->mode == CLIENT) {
    char *ip = (char *)&c->tip;
#if defined(__linux__)
    int err = exec_cmd("ip route add default via 10.0.0.%d dev %s metric 10",
                       ip[3], dev);
    if (!reconfig) {
      _CMD(err);
    }
    exec_cmd("ip route add %s via %s dev %s", c->vs, c->gw, c->mif);
    // v6
    exec_cmd("ip -6 route add ::/0 dev %s metric 10", dev);
#elif defined(__MACH__)
    exec_cmd("route delete default");
    int err = exec_cmd("route add default 10.0.0.%d -ifp %s", ip[3], dev);
    if (!reconfig) {
      _CMD(err);
    }
    exec_cmd("route add %s %s -ifp %s", c->vs, c->gw, c->mif);
    // v6
   // if (c->gw6[0] != 0) {
   //   exec_cmd("route delete -inet6 default");
   // }
    exec_cmd("route add -inet6 default fc00::%d -ifp %s", ip[3],
             dev);
#endif
  }
}

static void enable_forwarding() {
  int fd = open("/proc/sys/net/ipv4/conf/all/forwarding", O_RDWR);
  if (fd < 0 || write(fd, "1", 1) != 1) {
    err_exit("error enabling ipv4 forwarding");
  };
  close(fd);
  fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDWR);
  if (fd < 0 || write(fd, "1", 1) != 1) {
    err_exit("error enabling ipv6 forwarding");
  }
  close(fd);
}

#define SERVER_MTU 9001
static void setup_dev(ctx *c) {
  char *dev = c->tundev;
  //	_CMD(exec_cmd("ip link set dev %s multicast off", dev));
  if (c->mode == CLIENT) {
    int host = ((char *)&c->tip)[3];
#if defined(__MACH__)
    _CMD(exec_cmd(
        "ifconfig %s 10.0.0.%d 10.0.0.1 netmask 255.255.255.0 mtu %d up", dev,
        host, MTU - PROTO_HDR_LEN));
    _CMD(exec_cmd("ifconfig %s inet6 fc00::%d/120 add", dev, host));
#elif defined(__linux__)
    _CMD(exec_cmd("ip link set dev %s mtu %d up", dev, MTU - PROTO_HDR_LEN));
    _CMD(exec_cmd("ip address add 10.0.0.%d/24 dev %s", host, dev));
    // v6
    _CMD(exec_cmd("ip -6 addr add fc00::%d/120 dev %s", host, dev));
#endif
  } else {
    enable_forwarding();
    _CMD(exec_cmd("ip link set dev %s mtu %d up", dev, SERVER_MTU));
    _CMD(exec_cmd("ip address add 10.0.0.1/24 dev %s", dev));
    _CMD(exec_cmd(
        "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24",
        c->mif));
    // v6
    _CMD(exec_cmd("ip -6 addr add fc00::1/120 dev %s", dev));
    _CMD(exec_cmd(
        "ip6tables -t nat -A POSTROUTING -o %s -j MASQUERADE -s fc00::/120",
        c->mif));
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
#ifdef __MACH__
static int get_def_gw(ctx *c, int af) {
  int mib[6] = {CTL_NET, PF_ROUTE, 0, af, NET_RT_DUMP, 0};
  size_t len;
  int err = 0;
  if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
    perror("sysctl: get route table size");
    goto err_out_nofree;
  }

  char *buf = malloc(len);
  if (!buf) {
    perror("malloc");
    goto err_out_nofree;
  }

  if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
    perror("sysctl: get route table data");
    goto err_free_out;
  }

  struct rt_msghdr *rtm;
  char *ptr = buf;
  int ifindex = 0;

  while (ptr < buf + len) {
    rtm = (struct rt_msghdr *)ptr;
    ptr += rtm->rtm_msglen;
    if (rtm->rtm_flags & RTF_GATEWAY) {
      if (af == AF_INET) {
        struct sockaddr_in *sin =
            (struct sockaddr_in *)((struct sockaddr_in *)(rtm + 1) + 1);
        if (sin->sin_family == AF_INET && sin->sin_addr.s_addr != 0) {
          if (!inet_ntop(AF_INET, &sin->sin_addr, c->gw, sizeof(c->gw))) {
            perror("error retrieving INET gateway");
            goto err_free_out;
          }
          ifindex = rtm->rtm_index;
          break;
        }
      } else { // ipv6
        struct sockaddr_in6 *sin =
            (struct sockaddr_in6 *)((struct sockaddr_in6 *)(rtm + 1) + 1);
        if (sin->sin6_family == AF_INET6 &&
            !IN6_IS_ADDR_UNSPECIFIED(&sin->sin6_addr)) {
          if (!inet_ntop(AF_INET6, &sin->sin6_addr, c->gw6, sizeof(c->gw6))) {
            perror("error retrieving INET6 gateway");
            goto err_free_out;
          }
          ifindex = rtm->rtm_index;
          break;
        }
      }
    }
  }

  if (ifindex > 0) {
    if (af == AF_INET) {
      char ifname[IFNAMSIZ];
      if (if_indextoname(ifindex, ifname)) {
        strncpy(c->mif, ifname, sizeof(ifname));
      } else {
        perror("if_indextoname failed");
        goto err_free_out;
      }
    }
  } else {
    fprintf(stderr, "default gateway: unable to retrieve device name for %s\n", af == AF_INET ? "v4" : "v6");
    goto err_free_out;
  }
  err = 0;
  goto free_out;
err_out_nofree:
  err = -1;
  goto out;
err_free_out:
  err = -1;
free_out:
  free(buf);
out:
  return err;
}
#endif

static int get_def(ctx *c) {

#if defined(__linux__)

  FILE *fp = fopen("/proc/net/route", "r");
  if (!fp) {
    _log("error opening /proc/net/route");
    return -1;
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

#elif defined(__MACH__)
  if (get_def_gw(c, AF_INET) == -1) {
    return -1;
  }
  c->gw6[0] = 0;
  if (get_def_gw(c, AF_INET6) == -1) {
    _log("inet6 gateway not found");
  }
#endif
  return 0;
}

#if defined(__MACH__)
char ifname[IFNAMSIZ];

#endif

static void setup_tun(ctx *c) {
  int fd;
  const char *error = "error creating tunnel device";
#if defined(__linux__)
  fd = open("/dev/net/tun", O_RDWR);
  struct ifreq req;
  memset(&req, 0, sizeof(req));
  req.ifr_flags = IFF_TUN | IFF_NO_PI;

  strcpy(req.ifr_name, c->tundev);

  int r = ioctl(fd, TUNSETIFF, &req);

  if (r < 0) {
    err_exit(error);
  }
#elif defined(__MACH__)
  struct sockaddr_ctl addr;
  struct ctl_info info;
  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd < 0) {
    err_exit(error);
  }

  memset(&info, 0, sizeof(info));
  strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

  if (ioctl(fd, CTLIOCGINFO, &info) == -1) {
    close(fd);
    err_exit(error);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sc_len = sizeof(addr);
  addr.sc_family = AF_SYSTEM;
  addr.ss_sysaddr = AF_SYS_CONTROL;
  addr.sc_id = info.ctl_id;
  addr.sc_unit = 0;

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    err_exit(error);
  }

  socklen_t ifname_len = sizeof(ifname);
  if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) <
      0) {
    close(fd);
    err_exit(error);
  }
  c->tundev = ifname;
  pr_debug("tun device created: %s\n", ifname);
#endif
  setup_dev(c);
  c->tunfd = fd;
}

static inline int check_ip(unsigned char *ip) {
  if (!(((ip[0] >> 4) & 15) ^ 0x4)) {
    iphdr *h = (iphdr *)ip;
    if (!IN_MULTICAST((uint32_t)ntohl(h->daddr))) {
      return 1;
    }
  } else if (!(((ip[0] >> 4) & 15) ^ 0x6)) {
    ipv6hdr *h = (ipv6hdr *)ip;
    if (!IN6_IS_ADDR_MULTICAST(&h->daddr)) {
      return 1;
    }
  }
  return 0;
}

static inline int ip_host(unsigned char *ip) {
  if (!(((ip[0] >> 4) & 15) ^ 0x4)) {
    iphdr *h = (iphdr *)ip;
    return ((char *)&h->daddr)[3];
  } else if (!(((ip[0] >> 4) & 15) ^ 0x6)) {
    ipv6hdr *h = (ipv6hdr *)ip;
    return ((char *)&h->daddr)[15];
  }
  return 0;
}

#define write_all(wfunc, fd, buf, len, ...)                                    \
  ({                                                                           \
    int left = len;                                                            \
    unsigned char *b = buf;                                                    \
    do {                                                                       \
      errno = 0;                                                               \
      int w = wfunc(fd, b, left, ##__VA_ARGS__);                               \
      if (w == -1) {                                                           \
        perror("write error");                                                 \
        break;                                                                 \
      }                                                                        \
      left -= w;                                                               \
      if (!left) {                                                             \
        break;                                                                 \
      }                                                                        \
      b += w;                                                                  \
      _log("failed to write all at once, probably write queue is full\n");     \
      sched_yield();                                                           \
    } while (1);                                                               \
    errno;                                                                     \
  })

// server is .1, first client is .2, etc.
static inline int h2idx(int h) { return h - 2; }

static inline int idx2h(int i) { return i + 2; }

static inline int create_epollfd() {
#if defined(__linux__)
  int epollfd = epoll_create1(0);
  if (epollfd == -1) {
    err_exit("error creating epollfd");
  }
  return epollfd;
#elif defined(__MACH__)
  int kq = kqueue();
  if (kq == -1) {
    err_exit("error creating kqueue");
  }
  return kq;
#endif
}

static inline void epoll_add(int epollfd, int fd) {
#if defined(__linux__)
  struct epoll_event ev = {0};
  ev.events = EPOLLIN;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    err_exit("error epoll add");
  }
#elif defined(__MACH__)
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  if (kevent(epollfd, &ev, 1, NULL, 0, NULL) == -1) {
    err_exit("error creating kevent");
  }
#endif
}

static inline void epoll_del(int epollfd, int fd) {
#if defined(__linux__)
  if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
    err_exit("error epoll add");
  }
#elif defined(__MACH__)
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  if (kevent(epollfd, &ev, 1, NULL, 0, NULL) == -1) {
    err_exit("error deleting kevent");
  }
#endif
}

static inline int _epoll_wait(int epollfd, int fd, int timeout) {
#if defined(__linux__)
  struct epoll_event events[1];
  int nfds;
  if ((nfds = epoll_wait(epollfd, events, 1, timeout)) == -1) {
    perror("error epoll_wait");
    return -1;
  }
  return nfds;
#elif defined(__MACH__)
  struct kevent ev;
  long nsecs = timeout * 1000000ull;
#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000ull
#endif
  struct timespec to = {.tv_sec = nsecs / NSEC_PER_SEC,
                        .tv_nsec = nsecs % NSEC_PER_SEC};
  int n = kevent(epollfd, NULL, 0, &ev, 1, &to);
  if (n == -1) {
    perror("kevent error");
    return -1;
  }
  return n;
#endif
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

static int enc_and_send(ctx *c, int so, unsigned char *key, unsigned char *buf,
                        int len, struct sockaddr *addr, socklen_t sl) {
  assert(len <= c->enc_buf_len - GCM_IV_LEN - GCM_TAG_LEN);
  unsigned char *out = c->enc_buf;
  memcpy(out, c->iv, sizeof(c->iv));
  if (enc(c, c->iv, key, buf, len, out + sizeof(c->iv)) < 0) {
    _log("encryption error");
    return -1;
  }
  update_iv(c);
  int n = len + GCM_IV_LEN + GCM_TAG_LEN;
  c->tout += n;
  return write_all(sendto, so, out, n, 0, addr, sl);
}

static uint32_t check_used_ip(ctx *c, unsigned char *id) {
  uint32_t iid = *(uint32_t *)id;
  for (int i = 0; i < MAX_CONN; ++i) {
    if (c->clients[i].id == iid) {
      htab_remove(c->conns, (void *)c->clients[i].sessionid);
      return c->clients[i].tun_ipv4;
    }
  }
  return 0;
}

static inline void tun_fin(ctx *c, client *clt) {
  htab_remove(c->conns, (void *)clt->sessionid);
  _log("client disconnected: %x, session id: %x", clt->tun_ipv4,
       clt->sessionid);
  memset(clt, 0, sizeof(*clt));
}

static void client_initiated_fin(ctx *c, unsigned char *msg, int len) {
  if (len != (PROTO_HDR_LEN + GCM_IV_LEN + GCM_TAG_LEN + 4) ||
      msg[0] != PROTO_VERSION || msg[1] != PROTO_OP_FIN) {
    _log("invalid FIN");
    return;
  }
  uint32_t sid = *(uint32_t *)&msg[2];
  client *clt = htab_get(c->conns, (void *)sid);
  if (!clt) {
    _log("FIN: client not found, sid: %x", sid);
    return;
  }
  tun_fin(c, clt);
}

static void tun_handshake(ctx *c, int so, struct sockaddr_in *remote,
                          unsigned char *buf, int n) {
  if (n <= PROTO_HDR_LEN + GCM_IV_LEN + GCM_TAG_LEN) {
    _log("invalid incoming connection, addr: %x, port: %x",
         remote->sin_addr.s_addr, remote->sin_port);
    return;
  }
  int idx;
  buf += 2; // skip version & op
  n -= 2;
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
          _log("key mismatch");
          return;
        }
        if (strncmp((const char *)id, (const char *)kid, ID_LEN)) {
          _log("id mismatch");
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
        idx = h2idx(ip[3]);
        c->clients[idx].id = *(uint32_t *)kid;
        c->clients[idx].sessionid = c->sessionid++;
        c->clients[idx].key = key;
        c->clients[idx].addr = *remote;
        c->clients[idx].tun_ipv4 = *(uint32_t *)ip;
        pthread_mutex_init(&c->clients[idx].lock, NULL);
        // c->clients[idx].heartbeat = time(NULL);
        htab_insert(c->conns, (void *)c->clients[idx].sessionid,
                    &c->clients[idx]);
        _log("client connected, id: %x, tip: %x, addr: %x, port: %x, session "
             "id: %x",
             c->clients[idx].id, c->clients[idx].tun_ipv4,
             remote->sin_addr.s_addr, remote->sin_port,
             c->clients[idx].sessionid);
        unsigned char out[sizeof(ip) + sizeof(c->clients[idx].sessionid)];
        memcpy(out, ip, sizeof(ip));
        memcpy(out + sizeof(ip), &c->clients[idx].sessionid,
               sizeof(c->clients[idx].sessionid));
        if (enc_and_send(c, so, key, out, sizeof(out),
                         (struct sockaddr *)remote, sizeof(*remote))) {
          _log("error sending ip to client");
          tun_fin(c, &c->clients[idx]);
        }
        return;
        // established
      } else {
        _log("invalid incoming connection packet: addr: %x, port: %x, "
             "packet_len:%d",
             remote->sin_addr.s_addr, remote->sin_port, r);
      }
      return;
    }
  }
  _log("invalid id, addr: %x, port: %x", remote->sin_addr.s_addr,
       remote->sin_port);
}

static void *from_tun(void *hc) {
  ctx *c = (ctx *)hc;
  int sfd = c->sofd;
  int n;
  unsigned char *buf = c->recv_buf;
  int buf_len = c->recv_buf_len;
  unsigned char *dbuf = c->dec_buf;
  struct sockaddr_in ra = {0};
  socklen_t ral = sizeof(ra);
  while (1) {
    n = recvfrom(sfd, buf, buf_len, 0, (struct sockaddr *)&ra, &ral);
    if (n == 0 ||
        (n == -1 && errno == EMSGSIZE)) { // ignore message too long error
      continue;
    }
    if (n < 0) { // other errors, down
      break;
    }
    c->tin += n;
    int min_len = c->mode == SERVER
                      ? sizeof(c->iv) + GCM_TAG_LEN + PROTO_HDR_LEN
                      : sizeof(c->iv) + GCM_TAG_LEN;
    if (n < min_len) {
      _log("invalid packet");
      continue;
    }
    unsigned char *key;
    unsigned char *iv;
    unsigned char *msg;
    client *clt = NULL;
    if (c->mode == SERVER) {
      if (buf[0] != PROTO_VERSION) {
        _log("invalid protocol version: %x", buf[0]);
        continue;
      }
      int op = buf[1];
      switch (op) {
      case PROTO_OP_CONNECT:
        tun_handshake(c, sfd, &ra, buf, n);
        continue;
      case PROTO_OP_FIN:
        client_initiated_fin(c, buf, n);
        continue;
      default:
        _log("unknown op code: %x", op);
        continue;
      case PROTO_OP_FORWARD:
        // fallthrough
        break;
      }
      uint32_t sid = *(uint32_t *)&buf[2];
      clt = htab_get(c->conns, (void *)sid);
      if (!clt) {
        _log("session not found: %x, ignore", sid);
        // XXX: could have told the client to reconnect
        continue;
      }
      pr_debug("recv: session: %x, client addr: %x, port: %x\n", sid,
               clt->addr.sin_addr.s_addr, clt->addr.sin_port);
      key = clt->key;
      pthread_mutex_lock(&clt->lock);
      clt->addr = ra; // udpate with the latest address
      pthread_mutex_unlock(&clt->lock);
      n -= PROTO_HDR_LEN;
      iv = buf + PROTO_HDR_LEN;
      msg = buf + PROTO_HDR_LEN + GCM_IV_LEN;
    } else {
      key = c->key;
      iv = buf;
      msg = buf + GCM_IV_LEN;
    }

    unsigned char *pkt_start = dbuf + TUN_PKT_OFFSET;
    if (dec(c, iv, key, msg, n - sizeof(c->iv), pkt_start) < 0) {
      _log("decryption error");
      break;
    }

    pr_debug("from tun decrypted===========================\n");
    pr_debug_iphdr(pkt_start);
    pr_debug("from tun decrypted===========================end\n");

#ifdef __MACH__
    *((int *)dbuf) = 0x02000000; // macos: point to point proto
#endif
    int dlen = n - sizeof(c->iv) - GCM_TAG_LEN + TUN_PKT_OFFSET;
    if (write_all(write, c->tunfd, dbuf, dlen)) {
      if (c->mode == SERVER) {
        // probably client left
        tun_fin(c, clt);
      } else {
        // probably server down
        _log("error writing to tunnel device");
        break;
      }
    }
  }
  c->down = 1;
  perror("from_tun: DOWN");
  return NULL;
}

// static void server_multicast(ctx *c, unsigned char *buf, int len) {
//	pr_debug("server multicast\n");
//	hnod *nod;
//	htab_foreach(c->conns, nod) {
//		struct sockaddr_in *sa = nod->key;
//		client *clt = nod->data;
//		pr_debug("multicast to %x\n", clt->tun_ipv4);
//		if (enc_and_send(c, c->sofd, clt->key, buf, len, (struct
// sockaddr *)sa, sizeof(*sa))) { 			pr_debug("error
// enc_and_send\n"); 			break;
//		}
//	}
// }

static void *to_tun(void *hc) {
  ctx *c = (ctx *)hc;
  int fd = c->tunfd;
  int n;
  while ((n = read(fd, c->send_buf, c->send_buf_len)) > 0) {
    unsigned char *buf = c->send_buf + TUN_PKT_OFFSET;
    if (!check_ip(buf)) {
      pr_debug("multicast ignored\n");
      continue;
    }
    //		_log("to_tun: buf_len: %d, read: %d", c->send_buf_len, n);
    pr_debug("to tun===========================, len: %d\n", n);
    pr_debug_iphdr(buf);
    pr_debug("to tun===========================end\n");

    if (c->mode == SERVER) {
      client *clt;
      int host = ip_host(buf);
      int i = h2idx(host);
      if (i < 0 || i >= MAX_CONN || !c->clients[i].id) {
        _log("invalid host: %d, probably disconnected already", i);
        continue;
      }
      clt = &c->clients[i];
      unsigned char *key = clt->key;
      struct sockaddr_in to;
      pthread_mutex_lock(&clt->lock);
      to = clt->addr;
      pthread_mutex_unlock(&clt->lock);
      if (enc_and_send(c, c->sofd, key, buf, n, (struct sockaddr *)&to,
                       sizeof(to))) {
        _log("error enc_and_send");
        break;
      }
    } else {
      assert(n <= c->enc_buf_len - PROTO_HDR_LEN - GCM_IV_LEN - GCM_TAG_LEN);
      unsigned char *out = c->enc_buf;
      out[0] = PROTO_VERSION;
      out[1] = PROTO_OP_FORWARD;
      unsigned char *outb = out + 2;
      memcpy(outb, (void *)&c->sessionid, sizeof(c->sessionid));
      outb += sizeof(c->sessionid);
      memcpy(outb, c->iv, sizeof(c->iv));
      outb += sizeof(c->iv);

      if (enc(c, c->iv, c->key, buf, n, outb) < 0) {
        _log("encryption error");
        break;
      }
      int len = PROTO_HDR_LEN + GCM_IV_LEN + n + GCM_TAG_LEN;
      c->tout += len;
      pr_debug("to tun encrypted ===========================, len: %d\n", len);
      if (write_all(sendto, c->sofd, out, len, 0, (struct sockaddr *)&c->server,
                    sizeof(c->server))) {
        _log("error write");
        break;
      }
      update_iv(c);
    }
  }
  c->down = 1;
  perror("to_tun: DOWN");
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
  struct sockaddr_in a;
  socklen_t slen = sizeof(a);
  unsigned char resp[GCM_IV_LEN + GCM_TAG_LEN + 4 + sizeof(c->sessionid)];
  int n;
  unsigned char dbuf[4 + sizeof(c->sessionid)];

  ah.ai_family = AF_INET;
  ah.ai_socktype = SOCK_DGRAM;
  ah.ai_protocol = 0;
  struct addrinfo *ai;
  if (getaddrinfo(c->vs, NULL, &ah, &ai)) {
    err_exit("unable to resolve host");
  }
  int so = socket(PF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr = *(struct sockaddr_in *)ai->ai_addr;
  freeaddrinfo(ai);
  addr.sin_port = htons(c->port);
  c->server = addr;

  int epollfd = create_epollfd();
  // if (connect(so, (struct sockaddr *)&addr, sizeof(addr))) {
  //   goto err;
  // }
  c->sofd = so;
  set_nonblock(so);
  epoll_add(epollfd, so);

  unsigned char *id = c->id;
  int len = PROTO_HDR_LEN + ID_LEN + GCM_IV_LEN + GCM_TAG_LEN;
  unsigned char buf[64]; // reuse buf
  // 1 step, authenticate
  unsigned char *b = buf;
  b[0] = PROTO_VERSION;
  b[1] = PROTO_OP_CONNECT;
  b += 2;
  memcpy(b, id, ID_LEN);
  b += ID_LEN;
  memcpy(b, c->iv, sizeof(c->iv));
  b += sizeof(c->iv);
  if (enc(c, c->iv, c->key, id, ID_LEN, b)) {
    err_exit("err encrypting\n");
  }
  for (int i = 0; i < 3; ++i) {
    _log("connect %d", i);
    if (write_all(sendto, so, buf, len, 0, (struct sockaddr *)&addr,
                  sizeof(addr))) {
      goto err;
    }
    if (_epoll_wait(epollfd, so, (i + 1) * 2 * 1000) > 0) {
      goto gotresp;
    }
  }

  _log("unable to connect: peer not responding");
  goto err;

gotresp:
  n = recvfrom(so, resp, sizeof(resp), 0, (struct sockaddr *)&a, &slen);
  if (n <= 0) {
    _log("error recvfrom, probably server down");
    goto err;
  }
  assert(n == sizeof(resp));
  if (dec(c, resp, c->key, resp + GCM_IV_LEN, n - GCM_IV_LEN, dbuf)) {
    _log("error decrypting server response");
    // probably other packet arrived early? skip and try next
    goto gotresp;
  }
  c->tip = *(uint32_t *)dbuf;
  c->sessionid = *(uint32_t *)(dbuf + 4);

  update_iv(c);

  epoll_del(epollfd, so);
  close(epollfd);
  // connection established, switch to blocking mode
  set_block(so);
  setup_tun(c);

  start_forwarding(c);
  return 0;
err:
  close(so);
  close(epollfd);
  return -1;
}

#define USAGE                                                                  \
  "A simple tunnel using pre-shared key for encryption\n\n"                    \
  "usage:\n"                                                                   \
  "\t-s <vpn server> required for client mode\n"                               \
  "\t-p <port> optionl, the port to listen on in server mode, otherwise the "  \
  "server port to connect to, defualt is %d\n"                                 \
  "\t-i <interface> optional, the internet facing network interface\n"         \
  "\t-k <key file> optional, the key file to use, see the -g option below, "   \
  "default is 'tun.key' in cwd\n"                                              \
  "\t-g generate a key and ouput to stdout\n"                                  \
  "\t-n <gateway> optional, the default next hop to route the connection to "  \
  "vpn server\n"                                                               \
  "\t-d <device name> optional device name\n"                                  \
  "\t-P <control port> port for control\n"                                     \
  "\n"

#define B64C "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static int b64(unsigned char *b, int len, char *out) {
  int i = 0;
  int o = 0;
  for (; i < len; i += 3) {
    out[o++] = B64C[b[i] >> 2];
    out[o++] = B64C[((b[i] & 3) << 4) | (i + 1 < len ? (b[i + 1] >> 4) : 0)];
    out[o++] =
        i + 1 < len
            ? B64C[((b[i + 1] & 15) << 2) | (i + 2 < len ? (b[i + 2] >> 6) : 0)]
            : '=';
    out[o++] = i + 2 < len ? B64C[(b[i + 2] & 63)] : '=';
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
  for (; i + 4 <= len; i += 4) {
    unsigned char c1 = bi(b[i]);
    unsigned char c2 = bi(b[i + 1]);
    out[o++] = (c1 << 2) | (c2 >> 4);
    if (b[i + 2] == '=') {
      break;
    }
    unsigned char c3 = bi(b[i + 2]);
    out[o++] = ((c2 & 15) << 4) | (c3 >> 2);
    if (b[i + 3] == '=') {
      break;
    }
    unsigned char c4 = bi(b[i + 3]);
    out[o++] = ((c3 & 3) << 6) | c4;
  }
  return o;
}
static void getrandombytes(unsigned char *buf, size_t len);
static void genkey() {
  unsigned char rnd[ID_LEN + AES_KEY_LEN];
  getrandombytes(rnd, sizeof(rnd));

  char out[100];
  int n = b64(rnd, ID_LEN, out);
  out[n] = '\0';
  printf("%s:", out);
  n = b64(rnd + ID_LEN, AES_KEY_LEN, out);
  out[n] = '\0';
  printf("%s\n", out);
}

static void readkeys(char *keyfile, ctx *c) {
  unsigned char buf[100];
  FILE *fp = fopen(keyfile, "r");
  if (!fp) {
    err_exit("key file not found");
  }
  int m = c->mode == SERVER ? MAX_CONN : 1;
  for (int i = 0; i < m; ++i) {
  next:
    if (!fgets((char *)buf, sizeof(buf), fp)) {
      break;
    }
    unsigned char *p = buf;
    while (isspace(*p))
      p++;
    if (!p[0]) {
      goto next;
    }

    unsigned char *k = (unsigned char *)strchr((char *)p, ':');
    if (!k) {
      err_exit("error reading key file\n");
    }
    int d = k - p;
    assert(d == 8);
    assert(rb64(p, k - p, &c->keys[i * IK_LEN]) == ID_LEN);
    k++;
    int n = strlen((const char *)k);
    if (k[n - 1] == '\r' || k[n - 1] == '\n') {
      n--;
    }
    assert(rb64(k, n, &c->keys[i * IK_LEN + ID_LEN]) == AES_KEY_LEN);
  }
  fclose(fp);
}

static void cleanup(ctx *c) {
  _log("cleanup");
  if (c->to_tun) {
    pthread_cancel(c->to_tun);
    pthread_cancel(c->from_tun);
    pthread_join(c->to_tun, NULL);
    pthread_join(c->from_tun, NULL);
    c->to_tun = 0;
    c->from_tun = 0;
    close(c->tunfd);
    close(c->sofd);
  }
  if (c->mode == SERVER) {
    exec_cmd(
        "ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE -s fc00::/120",
        c->mif);
    exec_cmd(
        "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE -s 10.0.0.0/24",
        c->mif);
    exec_cmd("ip route delete 10.0.0.0/24 dev %s", c->tundev);
    exec_cmd("ip -6 route delete fc00::/120 dev %s", c->tundev);
    htab_free(c->conns);
  } else {
#if defined(__linux__)
    char *ip = (char *)&c->tip;
    exec_cmd("ip route delete %s via %s dev %s", c->vs, c->gw, c->mif);
    exec_cmd("ip route delete default via 10.0.0.%d metric 10", ip[3]);
    exec_cmd("ip -6 route delete ::/0 dev %s metric 10", c->tundev);
#elif defined(__MACH__)
    exec_cmd("route delete %s %s -ifp %s", c->vs, c->gw, c->mif);
    exec_cmd("route delete default");
    exec_cmd("route add default %s -ifp %s", c->gw, c->mif);
    char *ip = (char *)&c->tip;
    exec_cmd("route delete -inet6 default fc00::%d -ifp %s", ip[3], c->tundev);
    //if (c->gw6[0] != 0) {
      //exec_cmd("route add -inet6 default %s -ifp %s -ifscope %s", c->gw6, c->mif,
      //       c->mif);
    //}
#endif
  }
}

static int reconnect(ctx *c) {
  _log("reconnecting");
  cleanup(c);
  // retrieve the default gw again
  if (!get_def(c)) {
    _connect(c);
  } else {
    _log("error retrieving default gateway");
    return -1;
  }
  return 0;
}

static int _sendto(int so, char *buf, int len, struct sockaddr *addr,
                   socklen_t sl) {
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
    client *clt = nod->data;
    int s = snprintf(b, sizeof(buf) - len, "%x/%x\n", clt->addr.sin_addr.s_addr,
                     clt->tun_ipv4);
    b += s;
    len += s;
  }
  _sendto(so, buf, len, addr, sl);
}

static void client_quit(ctx *c) {
  unsigned char buf[PROTO_HDR_LEN + GCM_IV_LEN + GCM_TAG_LEN + 4];
  buf[0] = PROTO_VERSION;
  buf[1] = PROTO_OP_FIN;
  *(uint32_t *)&buf[2] = c->sessionid;
  unsigned char *b = buf + PROTO_HDR_LEN;
  memcpy(b, c->iv, sizeof(c->iv));
  b += sizeof(c->iv);
  if (enc(c, c->iv, c->key, (unsigned char *)"QUIT", 4, b) < 0) {
    _log("encryption error");
    return;
  }
  if (write_all(sendto, c->sofd, buf, sizeof(buf), 0,
                (struct sockaddr *)&c->server, sizeof(c->server))) {
    _log("error write");
  }
}

static void wait_for_stop(ctx *c, int port) {
  int so = bind_newsk(port, htonl(INADDR_LOOPBACK));
  set_nonblock(so);
  int epollfd = create_epollfd();
  epoll_add(epollfd, so);
  int nfds;
  time_t lastreconn = time(NULL);
  while ((nfds = _epoll_wait(epollfd, so, 500)) != -1 || errno == EINTR) {
    if (stop) {
      break;
    }
    if (!off && c->mode == CLIENT && c->down) {
      time_t now = time(NULL);
      if (now - lastreconn > 5) {
        _log("connection was down, last reconnect: %ld, now: %ld, reconnect",
             lastreconn, now);
        reconnect(c);
        // reconnect fail
        lastreconn = time(NULL);
      }
    } /* else {
             cleanup_dead_conns(c);
     }*/
    if (nfds == 0) {
      continue;
    }
    int n;
    char buf[1024];
    struct sockaddr_in ra = {0};
    socklen_t ral = sizeof(ra);
    while ((n = recvfrom(so, buf, sizeof(buf), 0, (struct sockaddr *)&ra,
                         &ral)) >= 0) {
      if (n >= 4 && !strncmp(buf, "stop", 4)) {
        _log("stop received");
        goto out;
      } else if (c->mode == CLIENT && n >= 3 && !strncmp(buf, "off", 3)) {
        _log("off received");
        if (!off) {
          off = 1;
          cleanup(c);
        } else {
          _log("already off");
        }
      } else if (c->mode == CLIENT && n >= 2 && !strncmp(buf, "on", 2)) {
        _log("on received");
        if (off) {
          if (!reconnect(c)) {
            off = 0;
          } else {
            _log("unable to set on");
          }
        } else {
          _log("already on");
        }
      } else if (c->mode == SERVER && n >= 4 && !strncmp(buf, "list", 4)) {
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
    client_quit(c);
  }
}

static void getrandombytes(unsigned char *buf, size_t len) {
#if defined(__linux__)
  if (getrandom(buf, len, 0) != len) {
    err_exit("error getrandom");
  }
#elif defined(__MACH__)
  if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess) {
    err_exit("error SecRandomCopyBytes");
  }
#endif
}

static void init_crypto(char *keyfile, ctx *c) {
  readkeys(keyfile, c);
  getrandombytes(c->iv, sizeof(c->iv));
  srand(*(unsigned int *)c->iv);
  c->cipher = EVP_aes_128_gcm();
  if (!(c->enc_ctx = EVP_CIPHER_CTX_new()) ||
      !(c->dec_ctx = EVP_CIPHER_CTX_new())) {
    _log("error create cipher context");
    exit(1);
  }
  if (c->mode == SERVER) {
    c->sessionid = rand();
  }
}

static void uninit_crypto(ctx *c) {
  EVP_CIPHER_free((EVP_CIPHER *)c->cipher);
  EVP_CIPHER_CTX_free(c->enc_ctx);
  EVP_CIPHER_CTX_free(c->dec_ctx);
}

static void init_server_ctx(ctx *c) {
  c->conns = htab_new(MAX_CONN, session_hash, session_equal);
  int n = MAX_CONN * sizeof(client);
  c->clients = malloc(n);
  memset(c->clients, 0, n);
}

static inline void start_server(ctx *c) {
  c->sofd = bind_newsk(c->port, INADDR_ANY);
  setup_tun(c);
  start_forwarding(c);
}

static void init_buffer(ctx *c) {
  int recv_buf_len;
  int send_buf_len;
  int enc_buf_len;
  if (c->mode == SERVER) {
    recv_buf_len = PACKET_MAX_LEN_C;
    send_buf_len = PACKET_MAX_LEN_S - GCM_IV_LEN - GCM_TAG_LEN;
    enc_buf_len = PACKET_MAX_LEN_S;
  } else {
    recv_buf_len = PACKET_MAX_LEN_S;
    send_buf_len = PACKET_MAX_LEN_C - GCM_IV_LEN - GCM_TAG_LEN - PROTO_HDR_LEN +
                   TUN_PKT_OFFSET;
    enc_buf_len = PACKET_MAX_LEN_C;
  }
  c->recv_buf_len = c->dec_buf_len = recv_buf_len;
  c->recv_buf = malloc(c->recv_buf_len);
  c->dec_buf_len += TUN_PKT_OFFSET;
  c->dec_buf = malloc(c->dec_buf_len);

  c->send_buf_len = send_buf_len;
  c->send_buf = malloc(c->send_buf_len);

  c->enc_buf_len = enc_buf_len;
  c->enc_buf = malloc(c->enc_buf_len);
  if (!c->recv_buf || !c->send_buf || !c->enc_buf || !c->dec_buf) {
    err_exit("error init_buffer");
  }
  _log("recv_buf_len: %d", c->recv_buf_len);
  _log("dec_buf_len: %d", c->dec_buf_len);
  _log("send_buf_len: %d", c->send_buf_len);
  _log("enc_buf_len: %d", c->enc_buf_len);
}

static void uninit_buffer(ctx *c) {
  free(c->recv_buf);
  free(c->dec_buf);
  free(c->send_buf);
  free(c->enc_buf);
}

static void daemonize() {
  pid_t pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    exit(0);
  }
  setsid();
  pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    exit(0);
  }
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
  int daemon = 0;
  // poor man's arg parse
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-s") && i + 1 < argc) {
      m = CLIENT;
      server = argv[i + 1];
      i += 1;
    } else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      port = atoi(argv[i + 1]);
      i += 1;
    } else if (!strcmp(argv[i], "-P") && i + 1 < argc) {
      sport = atoi(argv[i + 1]);
      i += 1;
    } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
      mif = argv[i + 1];
      i += 1;
    } else if (!strcmp(argv[i], "-h")) {
      printf(USAGE, PORT);
      exit(0);
    } else if (!strcmp(argv[i], "-k") && i + 1 < argc) {
      kf = argv[i + 1];
      i += 1;
    } else if (!strcmp(argv[i], "-g")) {
      genkey();
      exit(0);
    } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
      gw = argv[i + 1];
      i += 1;
    } else if (!strcmp(argv[i], "-d") && i + 1 < argc) {
      dev = argv[i + 1];
      i += 1;
    } else if (!strcmp(argv[i], "-D")) {
      daemon = 1;
    }
  }

  if (daemon)
    daemonize();

  debug_init();
  log_init();

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

  init_buffer(&context);

  if (get_def(&context)) {
    err_exit("error retrieving default gateway");
  }

  if (mif) {
    strncpy(context.mif, mif, sizeof(context.mif) - 1);
  }
  if (m == SERVER) {
    context.tundev = dev ? dev : SDEV;
    init_server_ctx(&context);
    start_server(&context);

  } else {
    if (!server) {
      err_exit("VPN server must be provided with -s\n");
    }
    if (gw) {
      strncpy(context.gw, gw, sizeof(context.gw) - 1);
    }
    context.tundev = dev ? dev : CDEV;
    context.vs = server;
    // connect
    for (int i = 0; _connect(&context);) {
#define RETRY_TO 5
      _log("connection failed, retry after %d seconds", RETRY_TO);
      sleep(RETRY_TO);
      _log("retrying... %d", i);
      if (i++ == 17280) {
        exit(EXIT_FAILURE);
      }
    }
  }
  setup_int();

  wait_for_stop(&context, sport);

  uninit_buffer(&context);
  uninit_crypto(&context);
  cleanup(&context);
  log_uninit();
  return 0;
}
