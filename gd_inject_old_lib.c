

void InitCtx(libnet_ctx *ctx)
{
   libnet_seed_prand(); 
   printf("Creating Libnet Socket\n"); 
   InitSocket(ctx);
}

int InitSocket(libnet_ctx* ctx)

{
  char *newdev,*device;
  char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
  struct sockaddr_in sin;
  struct libnet_link_int *network;    /* pointer to link interface struct */

  newdev = NULL;
  if ((ctx->device!=NULL) && (strstr(ctx->device,"AUTO")==NULL))
  {
    newdev = ctx->device;
  }

  if (ctx->device) {
      if (libnet_select_device(&sin, &newdev, err_buf) == -1)
      {
          libnet_error(LIBNET_ERR_FATAL, "libnet_select_device failed: %s - %s-\\
n", err_buf,device);
      }

      ctx->device = newdev;
      printf("device:\t\t\t\t%s\n", ctx->device);
  }

  ctx->sock = 0;

  if ((ctx->flag & ETHER_ENABLE) == 0) {
   ctx->device = NULL;
   if((ctx->sock = libnet_open_raw_sock(IPPROTO_RAW))==-1)
     libnet_error(LIBNET_ERR_FATAL, "Error opening socket.\n");
     ctx->network = NULL;
  }
  else {
    if ((ctx->network = libnet_open_link_interface(ctx->device, err_buf)) == NULL)
      libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s\n", 
		   err_buf);
  }

  return(1);
}


int ICMPInject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int packet_size;
  u_char *packet;
  unsigned int h;
  int size;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];
  struct _PACKET *e;

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  e = p->packet;
  if (e == NULL) {
    printf("ICMPInject: Error null packet\n");
    return(0);
  }
  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = h + LIBNET_IP_H + LIBNET_IP_H + e->buf_size;
  #ifdef DEBUG
  printf("Allocating Memory\n");
  #endif
  packet = (u_char*)malloc(sizeof(u_char)*packet_size);
  /* libnet_init_packet(packet_size, &packet); */
  if(!packet) {
    printf("ICMP Inject error %u\n",packet_size);
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
  }

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,packet);
  }


  if (libnet_build_ip(LIBNET_IP_H + e->buf_size, p->tos,
         p->ip_id, p->frag, p->ttl, p->proto, p->src_ip, p->dst_ip,
         NULL, 0, packet + h) == -1)
  {
     printf("ICMP Inject Error build_ip\n");
  }

/*
The packet type should be ICMP_UNREACH and the code should be one of the following:

ICMP_UNREACH_NET 	network is unreachable
ICMP_UNREACH_HOST 	host is unreachable
ICMP_UNREACH_PROTOCOL 	protocol is unreachable
ICMP_UNREACH_PORT 	port is unreachable
ICMP_UNREACH_NEEDFRAG 	fragmentation required but DF bit set
ICMP_UNREACH_SRCFAIL 	source routing failed
ICMP_UNREACH_NET_UNKOWN 	network is unknown
ICMP_UNREACH_HOST_PROHIB 	host is prohibited
ICMP_UNREACH_TOSNET 	IP TOS and network
ICMP_UNREACH_TOSHOST 	IP TOS and host
ICMP_UNREACH_FILTER_PROHIB 	prohibitive filtering
ICMP_UNREACH_HOST_PRECEDENCE 	host precedence
ICMP_UNREACH_PRECEDENCE_CUTOFF
*/

  if (libnet_build_icmp_unreach(ICMP_UNREACH, p->icmp_code, e->ip_len, e->tos,
			e->ip_id, e->frag, e->ttl, e->proto, e->src_ip,
			e->dst_ip, e->buffer, e->buf_size, 
			packet + h + LIBNET_IP_H) == -1)  
  {
     printf("ICMP Inject Error build_icmp\n");
  }

  if (libnet_do_checksum(packet + h, IPPROTO_ICMP , packet_size - LIBNET_IP_H) == -1)
  {
     printf("ICMP Inject Error checksum 1\n");
  }
  if (libnet_do_checksum(packet + h, IPPROTO_IP ,LIBNET_IP_H) == -1)
  {
     printf("ICMP Inject Error checksum 2\n");
  }

  #ifdef DEBUG
  printf("ICMP_INJECT - ready to send\n");
  #endif
  if (device && p->eth_dst) {
    libnet_write_link_layer(network, device, packet, packet_size);
  }
  else
    size = libnet_write_ip(sock, packet, packet_size);
  #ifdef DEBUG
  printf("ICMP Inject Sent %i\n",size);
  #endif
  /*libnet_destroy_packet((u_char**)&packet);*/
  /* Apparently lot of crash when getting to this free */
  free(packet);
  #ifdef DEBUG
  printf("ICMP Inject Successful\n");
  #endif
  return(size);
}


/****************************************************
 *         IP packet injector
 ****************************************************
 */
int inject(int sock, u_long src_ip, u_long dst_ip,
           u_short src_prt, u_short dst_prt,u_char protocol,
           u_short id,u_char ttl,u_char *buffer,int buf_size)
{
  int packet_size;
  u_char *packet;
  packet_size = LIBNET_IP_H + buf_size;
  libnet_init_packet(packet_size, &packet);
  if(!packet)
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
  libnet_build_ip(buf_size, IPTOS_PREC_PRIORITY,
            id, 0, ttl, protocol, src_ip, dst_ip,
            buffer, buf_size, packet);
  libnet_do_checksum(packet, protocol,buf_size);
  libnet_write_ip(sock, packet, packet_size);
  libnet_destroy_packet(&packet);
}

int ARPInject(int sock,struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int packet_size;
  u_char *packet;
  unsigned int h;
  int size;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];
  u_int16_t *uh_sum;
  u_char *daddr,*saddr;

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = h + LIBNET_ARP_H + p->buf_size;

  #ifdef DEBUG
  printf("ARPInject Start\n");
  #endif

  libnet_init_packet(packet_size, &packet);
  if(!packet)
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_ARP,NULL,0,packet);
  }
  saddr = (u_char*)&(p->src_ip);
  daddr = (u_char*)&(p->dst_ip);
  #ifdef DEBUG
  printf("Buffer size %i\n",p->buf_size);
  #endif
  size = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6 , 4, p->arp_type, p->eth_src, saddr,
                        p->eth_dst, daddr, p->buffer, p->buf_size, packet + h);
  if (size < 0) {
    printf("ARP Error\n");
  } 

  if (device) {
    #ifdef DEBUG
    printf("Write link %s\n",device);
    #endif
    size = libnet_write_link_layer(network, device, packet, packet_size);
    #ifdef DEBUG
    printf("Result : %i\n",size);
    #endif
  }
  else {
    size = libnet_write_ip(sock, packet, packet_size);
    #ifdef DEBUG
    printf("IPInject result 3 : %i\n",size);
    #endif
    /*printf("Old value %u\n",*uh_sum);*/
  }
 libnet_destroy_packet(&packet);
}

int ARPReqInject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int packet_size;
  u_char *packet;
  unsigned int h;
  int size;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];
  u_int16_t *uh_sum;
  struct  in_addr saddr,daddr;

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = h + LIBNET_ARP_H + p->buf_size;


  libnet_init_packet(packet_size, &packet);
  if(!packet)
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,packet);
  }

  saddr.s_addr = p->src_ip;
  daddr.s_addr = p->dst_ip;

  size = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6 , 4, ARPOP_REPLY, p->eth_src, inet_ntoa(saddr),
                        p->eth_dst, inet_ntoa(daddr), p->buffer, p->buf_size, packet + h);


  if (device) {
    size = libnet_write_link_layer(network, device, packet, packet_size);
  }
  else {
    size = libnet_write_ip(sock, packet, packet_size);
  }
 libnet_destroy_packet(&packet);
}

int IPInject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int packet_size;
  u_char *packet;
  unsigned int h;
  int size;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];
  u_int16_t *uh_sum;

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = h + LIBNET_IP_H + p->buf_size;

  libnet_init_packet(packet_size, &packet);
  if(!packet)
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,packet);
  }

  size = libnet_build_ip(p->buf_size, p->tos,
         p->ip_id, p->frag, p->ttl, p->proto, p->src_ip, p->dst_ip,
         p->buffer,p->buf_size, packet + h);

  if (p->ipcrc < 0) {
    size = libnet_do_checksum(packet + h, IPPROTO_IP ,LIBNET_IP_H);
  }
  else {
    /* set checksum manually */
    uh_sum = (u_int16_t*)(packet + h +  10);
    #ifdef DEBUG
    printf("Old value %u\n",*uh_sum);
    #endif
    *uh_sum = htons(p->ipcrc); 
    #ifdef DEBUG
    printf("Old value %u\n",*uh_sum);
    #endif
  }
  #ifdef DEBUG
  printf("IPInject result 2 : %i\n",size);
  #endif

  if (device) {
    size = libnet_write_link_layer(network, device, packet, packet_size);
    #ifdef DEBUG
    printf("Result : %i\n",size);
    #endif
  }
  else {
    size = libnet_write_ip(sock, packet, packet_size);
    #ifdef DEBUG
    printf("IPInject result 3 : %i\n",size);
    #endif
  }
 libnet_destroy_packet(&packet);
}


/****************************************************
 *         UDP packet injector
 ****************************************************
 */
int udpinject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int size,packet_size,res;
  u_char *packet;
  unsigned int h;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];
  u_int16_t *uh_sum;

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = h + LIBNET_IP_H + LIBNET_UDP_H + p->buf_size;

  #ifdef DEBUG 
  printf("Injecting UDP %i %u!!!\n",sock,packet_size);
  #endif

  /*
  *libnet_init_packet(packet_size, &packet);
  *if(!packet)
  *  libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
  */
  packet = (u_char*)malloc(sizeof(u_char)*packet_size);

  if (!packet) {
    printf("Can't allocate memory for UDP packet\n");
    exit(0);
  }

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,packet);
  }

  res = libnet_build_ip(LIBNET_UDP_H + p->buf_size, p->tos,
            p->ip_id, p->frag, p->ttl, IPPROTO_UDP, p->src_ip, p->dst_ip,
            NULL, 0, packet + h);
  #ifdef DEBUG
  printf("UDP frag %u\n",p->frag);
  printf("build_ip %i\n",res);
  #endif
  res = libnet_build_udp(p->src_prt,p->dst_prt,p->buffer,p->buf_size,
       	packet + LIBNET_IP_H + h);
  #ifdef DEBUG
  printf("build_udp %i\n",res);
  #endif


 
  if (libnet_do_checksum(packet + h, IPPROTO_IP ,LIBNET_IP_H) == -1)
    printf("failed to compute checksum\n\n\n");

  if (p->crc == -1) {
    if (libnet_do_checksum(packet + h, IPPROTO_UDP ,LIBNET_UDP_H + p->buf_size) == -1)
      printf("failed to compute checksum\n\n\n");
  }
  else {
   /* set udp checksum */
    uh_sum = (u_int16_t*)(packet + h +  LIBNET_IP_H + 6);
    *uh_sum = htons(p->crc);
  } 
  if (device) {
    libnet_write_link_layer(network, device, packet, packet_size);
  }
  else {
    size = libnet_write_ip(sock, packet, packet_size);
    #ifdef DEBUG
    printf("Sent %i bytes\n",size); 
    #endif 
  }
  
  /*libnet_destroy_packet(&packet);*/
  free(packet);
  return(1);
}


int tcpinject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_link_int *network;
  char *device;
  int sock;
  int packet_size,error,bufsize,size;
  u_short    esum,sum,cksum,addr[12];
  u_char *packet,*buffer,*tmp;
  unsigned int h;
  struct ether_addr *eth_local;
  char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */

  device = ctx->device;
  network = ctx->network;
  sock = ctx->sock;

  if (device)
    h = LIBNET_ETH_H;
  else
    h = 0;

  packet_size = 0; 

  if (p->gen_size && (p->buf_size <= p->gen_size)) {
    #ifdef DEBUG
    printf("Adjusting TCP data\n");
    #endif
    buffer = (char*)malloc(p->gen_size);
    if (!buffer) {
      printf("Maloc Error - can't get memory for buffer\n");
    }
    if (p->buf_size > 0) {
      #ifdef DEBUG
      printf("Starting memcpy\n");
      #endif	
      memcpy(buffer,p->buffer,p->gen_size - p->buf_size);
    }
    GenerateData(buffer + p->buf_size , p->gen_size - p->buf_size, p->addhttpend);
    packet_size = p->gen_size - p->buf_size;
    bufsize = p->gen_size;
  }  

  packet_size += (h + LIBNET_IP_H + LIBNET_TCP_H + p->buf_size);

  if (!p) {
    printf("tcpinject fatal error\n");
    exit(0);
  }

  #ifdef DEBUG
  printf("TCP Inject packet size %u\n",packet_size);
  #endif

  if (libnet_init_packet(packet_size, &packet) < 0) {
    printf("libnet_init_packet init failure, trying malloc\n");
    packet = (u_char*)malloc(sizeof(u_char)*packet_size);
  }

  /*packet = (u_char*)malloc(sizeof(u_char)*packet_size);*/

  if(!packet) {
    printf("Malloc error\n");
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
  }

  #ifdef DEBUG
  printf("TCP Inject libnet_init_packet OK\n");
  #endif

  if (device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(network,device,err_buf);
      if (!eth_local)
        printf("Libnet error in get_hwaddr %s\n",err_buf);

      p->eth_src = (u_char*)eth_local->ether_addr_octet;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,packet);
  }

  #ifdef DEBUG
    printf("tcpinject: bufsize %u\n",p->buf_size);
  #endif

  libnet_build_ip(packet_size - h -  LIBNET_IP_H, p->tos,
            p->ip_id, 0, p->ttl, IPPROTO_TCP, p->src_ip, p->dst_ip,
            NULL, 0, packet + h);
  
  if (p->seq == 0) {
    p->seq = libnet_get_prand(LIBNET_PRu32);
    #ifdef DEBUG
    printf("New seq %u\n",p->seq);
    #endif
  }

  if (p->tcpopt) {
    #ifdef DEBUG
      printf("TCP OPTION turned on\n");
    #endif
    buffer = NULL;
    bufsize = 0;
  }
  else if (p->gen_size == 0) {
    #ifdef DEBUG
      printf("TCP OPTION turned off\n");
    #endif
    buffer = p->buffer;
    bufsize = p->buf_size;
  }

  #ifdef DEBUG
  printf("bufsize %u\n",bufsize);
  #endif

  libnet_build_tcp(p->src_prt,p->dst_prt,p->seq,p->ack,p->flags,p->win,p->urg,buffer, bufsize,packet + LIBNET_IP_H + h);

  if (p->tcpopt) {
    bufsize = libnet_insert_tcpo((struct tcpoption*)p->buffer,p->buf_size,packet + h);
    #ifdef DEBUG
    printf("Insert option result : %i fromt %i %x\n",bufsize,p->buf_size,p->buffer);
    #endif
  }

  if (libnet_do_checksum(packet + h, IPPROTO_IP ,LIBNET_IP_H) == -1)
    printf("failed to compute checksum\n\n\n");

  if (libnet_do_checksum(packet + h, IPPROTO_TCP , packet_size - h -  LIBNET_IP_H) == -1)
    printf("failed to compute checksum\n\n\n");
 
  if (device) {
  /*  libnet_hex_dump(packet,packet_size,1,stdout);*/
    libnet_write_link_layer(network, device, packet, packet_size);
  }
  else
    libnet_write_ip(sock, packet, packet_size);

  /*libnet_destroy_packet(&packet);*/
  free(packet);
  if (p->gen_size) {
    free(buffer);
  }
  return(1);
}
