

void libnet_ctx InitCtx(libnet_ctx *ctx);

int ARPInject(struct _PACKET *p, libnet_ctx *ctx);
int IPInject(struct _PACKET *p, libnet_ctx *ctx);
int udpinject(struct _PACKET *p, libnet_ctx *ctx);
int tcpinject(struct _PACKET *p, libnet_ctx *ctx);
int ICMPInject(struct _PACKET *p,libnet_ctx *ctx);

#ifdef LIBNET_IPV4_H 
/**********************
 * new libnet library *
 **********************/
typedef struct libnet_ctx_ {
  libnet_t *plib;
  libnet_ptag_t tag_tcp, tag_ip, tag_ether, tag_icmp, tag_udp, tag_options;
  libnet_ptag_t tag_icmp, tag_arp;
  char *device;
  u_char flag,fast_mode;
  char errbuff[LIBNET_ERRBUF_SIZE];
} libnet_ctx;

libnet_ctx *InitCtx(char *device, char *errbuff);
int newetherinject(struct _PACKET *p, libnet_ctx *ctx);

#else
/**********************
 * old libnet library *
 **********************/

typedef struct libnet_ctx_ {
  struct libnet_link_int *network;
  char *device;
  int sock;
  u_char flag,fast_mode;
} libnet_ctx;



int inject(int sock, u_long src_ip, u_long dst_ip,
           u_short src_prt, u_short dst_prt,u_char protocol,
           u_short id,u_char ttl,u_char *buffer,int buf_size);

int ARPReqInject(struct _PACKET *p, libnet_ctx *ctx);

#endif
