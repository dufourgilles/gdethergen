/********************************************************************
 *   Support for new libnet library
 ********************************************************************/



void InitCtx(libnet_ctx *ctx)
{

  if (ctx->device) {
    ctx->plib = libnet_init(LIBNET_LINK, ctx->device, ctx->errbuf);
  }
  else {
    ctx->plib = libnet_init(LIBNET_RAW4, ctx->device, ctx->errbuf);
  }
  
  if (!ctx->plib) {
    printf("libnet_init failure\n");
    exit(0);
  }
  ctx->tag_tcp = 0;
  ctx->tag_ip = 0;
  ctx->tag_udp = 0;
  ctx->tag_icmp = 0;
  ctx->tag_ether = 0;
  ctx->tag_options = 0;
  ctx->tag_icmp = 0;
  ctx->tag_arp = 0;

  libnet_seed_prand(ctx->plib);

  return;
}




int IPInject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct libnet_ether_addr *eth_local;

  ctx->tag_ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + + p->buf_size, p->tos,
            p->ip_id, p->ipcrc, p->ttl, IPPROTO_TCP, p->src_ip, p->dst_ip,
            NULL, 0, ctx->plib, ctx->tag_ip );
  
  if (ctx->tag_ip <= 0) {
     printf("Error in libnet_build_ipv4\n\t%s\n",libnet_geterror(ctx->plib);
     return(0);
  }

  if (!newetherinject(struct _PACKET *p, libnet_ctx *ctx))
    return(0);

  if (libnet_write(ctx->plib) < 0) {
    printf("Error in libnet_write\n\t%s\n",libnet_geterror(ctx->plib);
    return(0);
  }

  return(1);
}

int newetherinject(struct _PACKET *p, libnet_ctx *ctx)
{
  if (ctx->device) {
    if (p->eth_src == NULL) {
      eth_local = libnet_get_hwaddr(plib);
      if (!eth_local) 
        printf("Libnet error in get_hwaddr %s\n",libnet_geterror(plib));
        return(0);
      }
      p->eth_src = (u_char*)eth_local;
    }
    if (p->eth_dst == NULL) {
      printf("Error: No destination mac address available\n");
      return(0);
    }
    ctx->tag_ether = libnet_build_ethernet(p->eth_dst,p->eth_src,ETHERTYPE_IP,NULL,0,ctx->plib,ctx->tag_ether);
    if (ctx->tag_ether <= 0) {
      printf("Error in libnet_build_ethernet\n\t%s\n",libnet_geterror(ctx->plib);
      return(0);
    }
  }
  return(1);
}

int tcpinject(struct _PACKET *p, libnet_ctx *ctx)
{

  u_char *buffer;
  int h,res;

  if (!ctx) {
    printf("Null context\n");
    return(0);
  }
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
    bufsize = p->gen_size;
  }  

  #ifdef DEBUG
  printf("TCP Inject packet size %u\n",packet_size);
  printf("tcpinject: bufsize %u\n",p->buf_size);
  #endif


  if (p->seq == 0) {
    p->seq = libnet_get_prand(LIBNET_PRu32);
    #ifdef DEBUG
    printf("New seq %u\n",p->seq);
    #endif
  }
  h = 0;
  if (p->tcpopt) {
    #ifdef DEBUG
      printf("TCP OPTION turned on\n");
    #endif
    buffer = NULL;
    bufsize = 0;
    ctx->tag_option = libnet_build_tcp_options(p->buffer,p->buf_size,ctx->plib, ctx->tag_option); 
    if (ctx->tag_option <= 0) {
      printf("Error in libnet_build_tcp_options\n\t%s\n",libnet_geterror(ctx->plib);
      return(0);
    }
    h = p->buf_size;
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

  ctx->tag_tcp = libnet_build_tcp(p->src_prt,p->dst_prt,p->seq,p->ack,p->flags,
					    p->win,0, LIBNET_TCP_H + h + bufsize, p->urg,buffer, bufsize,
					    ctx->plib, ctx->tag_tcp);

  if (ctx->tag_tcp <= 0) {
     printf("Error in libnet_build_tcp\n\t%s\n",libnet_geterror(ctx->plib);
     return(0);
  }
  
  res = newipinject(p, ctx);

  if (p->gen_size) {
    free(buffer);
  }
  return(res);
}



int udpinject(struct _PACKET *p, libnet_ctx *ctx)
{
  int res;


  #ifdef DEBUG 
  printf("Injecting UDP %i %u!!!\n",sock,packet_size);
  #endif

  ctx->tag_udp = libnet_build_udp(p->src_prt,p->dst_prt, LIBNET_UDP_H + p->buf_size, p->crc,
					    p->buffer,p->buf_size, ctx->plib, ctx->tag_udp);

  if (ctx->tag_udp <= 0) {
     printf("Error in libnet_build_udp\n\t%s\n",libnet_geterror(ctx->plib);
     return(0);
  }

  res = newipinject(p, ctx);

  return(res);
}



int ARPInject(struct _PACKET *p, libnet_ctx *ctx)
{
  u_char *daddr,*saddr;

  #ifdef DEBUG
  printf("ARPInject Start\n");
  #endif

  saddr = (u_char*)&(p->src_ip);
  daddr = (u_char*)&(p->dst_ip);

  ctx->tag_arp = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6 , 4, p->arp_type, p->eth_src, 
					saddr, p->eth_dst, daddr, p->buffer, p->buf_size,
				 	ctx->plib, ctx->tag_arp);

  if (ctx->tag_arp <= 0) {
     printf("Error in libnet_build_arp\n\t%s\n",libnet_geterror(ctx->plib);
     return(0);
  }

  if (!newetherinject(struct _PACKET *p, libnet_ctx *ctx))
    return(0);

  if (libnet_write(ctx->plib) < 0) {
    printf("Error in libnet_write\n\t%s\n",libnet_geterror(ctx->plib);
    return(0);
  }
  
}


int ICMPInject(struct _PACKET *p, libnet_ctx *ctx)
{
  struct _PACKET *e;
  int res;

  e = p->packet;
  if (e == NULL) {
    printf("ICMPInject: Error null packet\n");
    return(0);
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

  ctx->tag_icmp = libnet_build_icmpv4_unreach(ICMP_UNREACH, p->icmp_code, 0, e->ip_len, e->tos,
			e->ip_id, e->frag, e->ttl, e->proto, e->ipcrc, e->src_ip,
			e->dst_ip, e->buffer, e->buf_size, 
			ctx->plib, ctx->tag_icmp)  


  if (ctx->tag_icmp <= 0) {
     printf("Error in libnet_build_icmp\n\t%s\n",libnet_geterror(ctx->plib);
     return(0);
  }

  #ifdef DEBUG
  printf("ICMP_INJECT - ready to send\n");
  #endif

  res = newipinject(p, ctx);

  return(res);
}

