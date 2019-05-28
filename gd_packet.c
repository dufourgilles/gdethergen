#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "gdethergen.h"
#include "gd_packet.h"


/**********************
 *
 * -ipsrc = IP SOURCE
 * -ipdst = IP DESTINATION
 * -proto = Protocol Number
 * -portsrc = PORT SOURCE
 * -portdst = PORT DESTINATION
 * -ttl = IP TTL
 * -frag = IP Fragment
 * -ipid = IP PACKET ID
 * -seq = TCP Sequence number
 * -ack
 * -TSYN = TCP SYN FLAG
 * -TFIN
 * -TACK
 * -TRST
 * -payload = BINARY FILE WITH PAYLOAD DATA
 * -newsend
 * -newrcv
 *
 *
 *************************************************/

void InitPack(struct _PACKET *p) {
  p->ip_len = 0;
  p->packet = NULL;
  p->icmp_code = 0;
  p->src_ip = 0;
  p->dst_ip = 0;
  p->win = 8192;
  p->urg = 0;
  p->tos = 0;
  p->ttl = 64;
  p->flags = 0;
  p->tcpopt = 0;
  p->seq = 0;
  p->cfg_seq = 0;
  p->ack = 0;
  p->cfg_ack = 0;
  p->ip_id = 666;
  p->frag = 0;
  p->buffer = NULL;
  p->buf_size = 0;
  p->gdipgen_type = GENTYPE_SEND;
  p->src_prt = 0;
  p->cfg_src_prt = 0;
  p->dst_prt = 0;
  p->cfg_dst_prt = 0;
  p->delay = 0;
  p->eth_dst = NULL;
  p->eth_src = NULL;
  p->proto = 6;
  p->quantity = 1;
  p->repeat = 1;
  p->topacket = 0;
  p->minlen = 0;
  p->inc = 0;
  p->inctype = INC_TYPE_TCP_SRC;
  p->packet_id = 0;
  p->next = 0;
  p->prev = 0;
  p->crc = -1;
  p->ipcrc = -1;
  p->gen_size = 0;
  p->addhttpend = 0;
  p->arp_type = 0; 
}

void DestroyPacket(struct _PACKET *p) {
  if (p->buffer)
    free(p->buffer);
  if (p->eth_dst)
    free(p->eth_dst);
  if (p->eth_src)
    free(p->eth_src);
  if (p->packet) {
    DestroyPacket(p->packet);
  }
}
/* return a value > 0 if a new send packet is needed 
 * a value < 0 if a new received packet is needed */


int SetPack(struct _PACKET *p,void **param,int *pos) {
  struct ether_addr *eth;
  #ifdef DEBUG
    printf("Entering SetPack %i\n",*pos);
  #endif
  if (strcmp((char*)param[*pos],"-delay") == 0) {
    *pos += 1;
    p->delay = (uint)atoi((char*)param[*pos]);
    *pos += 1;
    return(0);
  }

  if (strcmp((char*)param[*pos],"-newsend") == 0) {
    *pos += 1;
    return(GENTYPE_SEND);
  }
  if (strcmp((char*)param[*pos],"-newrcv") == 0) {
    *pos += 1;
    return(GENTYPE_RECEIVE);
  }
  if (strcmp((char*)param[*pos],"-server") == 0) {
    *pos += 1;
    return(GENTYPE_SERVER);
  }
/*
ARPOP_REQUEST   ARP request
ARPOP_REPLY     ARP reply
ARPOP_REVREQUEST        RARP request
ARPOP_REVREPLY  RARP reply
ARPOP_INVREQUEST        request to identify peer
ARPOP_INVREPLY  reply identifying peer
*/

  if (strcmp((char*)param[*pos],"-arptype") == 0) {
    *pos += 1;
    p->proto = 0;
    p->arp_type = atoi((char*)param[*pos]);
    *pos += 1;
    return(0);
  }

  if (strcmp((char*)param[*pos],"-ipsrc") == 0) {
    *pos += 1;
    p->src_ip = inet_addr((char*)param[*pos]);
    *pos += 1;
  #ifdef DEBUG
    printf("found -ipsrc\n");
  #endif
    return(0);
  }
  if (strcmp((char*)param[*pos],"-count") == 0) {
    *pos += 1;
    p->count = atoi((char*)param[*pos]);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-ipdst") == 0) {
    *pos += 1;
    p->dst_ip = inet_addr((char*)param[*pos]);
    *pos += 1;
#ifdef DEBUG
    printf("found -ipdst\n");
#endif
    return(0);
  }
  if (strcmp((char*)param[*pos],"-ethsrc") == 0) {
    *pos += 1;
    eth = (struct ether_addr*)ether_aton((char*)param[*pos]);
    if (!eth) {
      printf("ERROR: incorrect mac address format\n");
      exit(1);
    }
    *pos += 1;
    p->eth_src = (u_char*)malloc(6);
    memcpy(p->eth_src,eth,6);
    return(0);
  }
  if (strcmp((char*)param[*pos],"-ethdst") == 0) {
    *pos += 1;
    eth = (struct ether_addr*)ether_aton((char*)param[*pos]);
    if (!eth) {
      printf("ERROR: incorrect mac address format\n");
      exit(1);
    }
    *pos += 1;
    p->eth_dst = (u_char*)malloc(6);   
    memcpy(p->eth_dst,eth,6);
    return(0);
  }
  if (strcmp((char*)param[*pos],"-portsrc") == 0) {
    *pos += 1;
    p->src_prt=atoi(param[*pos]);
    p->cfg_src_prt = p->src_prt;
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-portdst") == 0) {
    *pos += 1;
    p->dst_prt=atoi(param[*pos]);
    p->cfg_dst_prt = p->dst_prt;
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-ipid") == 0) {
    *pos += 1;
    p->ip_id = (u_short)atoi(param[*pos]);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-icmp_code") == 0) {
    *pos += 1;
    p->icmp_code = (u_short)atoi(param[*pos]);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-frag") == 0) {
    *pos += 1;
    p->frag = (u_short)atoi(param[*pos]);
    printf("Set frag to %i\n",p->frag);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-df") == 0) {
    *pos += 1;
    p->frag |= 0x4000;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-mf") == 0) {
    *pos += 1;
    p->frag |= 0x2000;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-offset") == 0) {
    *pos += 1;
    p->frag = (((u_short)atoi(param[*pos]) / 8) & 0x1FFF) + (p->frag & 0x6000);
    printf("Set frag to %i\n",p->frag);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-ttl") == 0) {
    *pos += 1;
    p->ttl = (u_char)atoi(param[*pos]);
    *pos += 1;
#ifdef DEBUG
        printf("found -ttl\n");
#endif
    return(0);
  }
  if (strcmp((char*)param[*pos],"-tos") == 0) {
    *pos += 1;
    p->tos = (u_char)atoi(param[*pos]);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-proto") == 0) {
    *pos += 1;
    p->proto = (u_char)atoi(param[*pos]);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-tcpopt") == 0) {
    *pos += 1;
    p->tcpopt = 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-TFIN") == 0) {
    *pos += 1;
    p->flags |= TH_FIN;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-TSYN") == 0) {
    *pos += 1;
    p->flags |= TH_SYN;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-TRST") == 0) {
    *pos += 1;
    p->flags |= TH_RST;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-TACK") == 0) {
    *pos += 1;
    p->flags |= TH_ACK;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-TPUSH") == 0) {
    *pos += 1;
    p->flags |= TH_PUSH;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-win") == 0) {
    *pos += 1;
    p->win = atoi(param[*pos]);
    *pos += 1;
    return(0);
  } 
  if (strcmp((char*)param[*pos],"-payload") == 0) {
    *pos += 1;
    p->buffer = (u_char*)malloc(sizeof(char)*2000);
    p->buf_size = ReadBuffer((char*)param[*pos],p->buffer,2000,0);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-header") == 0) {
    *pos += 1;
    p->buffer = (u_char*)malloc(sizeof(char)*2000);
    p->buf_size = ReadBuffer((char*)param[*pos],p->buffer,2000,1);
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-hex") == 0) {
    *pos += 1;
    p->buffer = (u_char*)malloc(sizeof(char)*2000);
    p->buf_size = ReadHexBuffer(param[*pos],p->buffer);
    /*printf("Debug - buffer 0x%x 0x%x\n",p->buffer[0],p->buffer[1]);*/
    *pos += 1;
    return(0);
  }
  if (strcmp((char*)param[*pos],"-quantity") == 0) {
    *pos += 1;
      p->quantity = (u_long)atoll(param[*pos]);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-repeat") == 0) {
    *pos += 1;
      p->repeat = (u_long)atoll(param[*pos]);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-minlen") == 0) {
    *pos += 1;
      p->minlen = 40 + (u_long)atoll(param[*pos]);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-gotonext") == 0) {
    *pos += 1;
      p->topacket = (u_long)atoll(param[*pos]);
      p->inc = 1;
      printf("Setting goto packet id %u\n",p->topacket);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-gototype") == 0) {
    *pos += 1;
      p->inctype = (int)atoi(param[*pos]);
      printf("Setting goto type to %u\n",p->inctype);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-goto") == 0) {
    *pos += 1;
      p->topacket = (u_long)atoll(param[*pos]);
      p->inc = 0;
      printf("Setting goto packet id %u\n",p->topacket);
      *pos += 1;
      p->next = p->topacket - 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-seq") == 0) {
      *pos += 1;
      p->seq= (u_long)atoll(param[*pos]);
      p->cfg_seq = p->seq;
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-ack") == 0) {
      *pos += 1;
       p->ack= (u_long)atoll(param[*pos]);
       p->cfg_ack = p->ack;
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-gensize") == 0) {
      *pos += 1;
       p->gen_size= atoi(param[*pos]);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-crc") == 0) {
      *pos += 1;
       p->crc = (int)atoi(param[*pos]);
      *pos += 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-addhttpend") == 0) {
      *pos += 1;
       p->addhttpend = 1;
      return(0);
  }
  if (strcmp((char*)param[*pos],"-ipcrc") == 0) {
      *pos += 1;
       p->ipcrc = (int)atoi(param[*pos]);
      *pos += 1;
      return(0);
  }
  else {
    printf("Unknown parameter -%s- at pos %i\n",(char*)param[*pos],*pos);
    exit(0);
  }
}

int SetType(int type, int mode) {
  if (mode == GENTYPE_CLIENT)
    return type;
  else {
    switch(type) { 
    case GENTYPE_SEND:
      /*printf("Changing type from send to receive\n");*/
      return (GENTYPE_RECEIVE);
      break;
    case GENTYPE_RECEIVE:
      /*printf("Changing type from receive to send\n");*/
      return(GENTYPE_SEND);
      break;
    default:
      return(type);
      break;
    }
  }
  return(type);
}   


