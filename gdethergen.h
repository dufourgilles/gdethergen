#ifndef GDETHERGEN__
#define GDETHERGEN__

#define VERSION "3.1.1"

#define INC_TYPE_IP_SRC 	1
#define INC_TYPE_IP_DST		2
#define INC_TYPE_TCP_SRC	4
#define INC_TYPE_TCP_DST	8

#define FAST_MODE 0x2
#define ETHER_ENABLE 0x1

#define ETHER_ADDR_LEN 6
#define tcp_seq u_int32_t
#define PIPE_READ 0
#define PIPE_WRITE 1
#define size_ethernet sizeof(struct sniff_ethernet)
#define size_ip sizeof(struct sniff_ip)
#define size_tcp sizeof(struct sniff_tcp)
#define SEM_ID    250
#define MAX_PACKET 64
#define MAX_TOKEN  4096

#define GENTYPE_SEND 	1
#define GENTYPE_RECEIVE 2 
#define GENTYPE_DELAY 	3
#define GENTYPE_SERVER	4
#define GENTYPE_CLIENT	5


#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
  int val;                  /* value for SETVAL */
  struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
  unsigned short *array;    /* array for GETALL, SETALL */
                           /* Linux specific part: */
  struct seminfo *__buf;    /* buffer for IPC_INFO */
 };
#endif


struct mtcpoption
{
    u_char tcpopt_list[40];
};

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip {
 #if BYTE_ORDER == LITTLE_ENDIAN
  u_int ip_hl:4, /* header length */
  ip_v:4; /* version */
  #if BYTE_ORDER == BIG_ENDIAN
  u_int ip_v:4, /* version */
  ip_hl:4; /* header length */
  #endif
  #endif /* not _IP_VHL */
  u_char ip_tos; /* type of service */
  u_short ip_len; /* total length */
  u_short ip_id; /* identification */
  u_short ip_off; /* fragment offset field */
  #define IP_RF 0x8000 /* reserved fragment flag */
  #define IP_DF 0x4000 /* dont fragment flag */
  #define IP_MF 0x2000 /* more fragments flag */
  #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
  u_char ip_ttl; /* time to live */
  u_char ip_p; /* protocol */
  u_short ip_sum; /* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
/* TCP header */
struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq; /* sequence number */
  tcp_seq th_ack; /* acknowledgement number */
  #if BYTE_ORDER == LITTLE_ENDIAN
  u_int th_x2:4, /* (unused) */
  th_off:4; /* data offset */
  #endif
  #if BYTE_ORDER == BIG_ENDIAN
  u_int th_off:4, /* data offset */
  th_x2:4; /* (unused) */
  #endif
  u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

struct sniff_udp {
         u_int16_t uh_sport; /* source port */
         u_int16_t uh_dport; /* destination port */
         u_int16_t uh_ulen; /* udp length */
         u_int16_t uh_sum; /* udp checksum */
}; 

#define ARP_RESP 1
#define ARP_REQ  2
/*
ARPOP_REQUEST 	ARP request
ARPOP_REPLY 	ARP reply
ARPOP_REVREQUEST 	RARP request
ARPOP_REVREPLY 	RARP reply
ARPOP_INVREQUEST  	request to identify peer
ARPOP_INVREPLY 	reply identifying peer
*/

struct _PACKET {
  u_long src_ip, dst_ip,buf_size;
  u_short frag,src_prt,cfg_src_prt, dst_prt,cfg_dst_prt,ip_id,win,urg,tcpopt;
  u_short icmp_code,ip_len;
  int gdipgen_type,inctype,crc,ipcrc;
  uint delay,count;
  u_char tos,proto,ttl,flags;
  u_long id,seq,ack,cfg_seq,cfg_ack;
  char *buffer;
  u_char *eth_dst,*eth_src;
  u_short eth_id;
  u_long quantity,repeat;
  u_long topacket,minlen;
  u_long packet_id;
  int next,prev;
  char inc,addhttpend,arp_type;
  int gen_size;
  struct _PACKET *packet;
} PACKET;

#endif

void do_child(libnet_ctx *ctx,
	struct _PACKET *pack,int packtot,int *pipes, char *filter_app,int semid
	);
void do_parent(libnet_ctx *ctx,struct _PACKET *pack,int packtot,int *pipes,int semid);


