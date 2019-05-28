#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "gdethergen.h"
#include "gd_packet.h"

int exp(int a, int b) {
  int res;

  res = 1;
  while(b) {
    res = res * a;
    b--;
  }
  return(res);
}

int atoh(char *s)
{
  int i,len;
  int res,c;
  char *ptr;

  res = 0;
  len = strlen(s);
  len--;
  i = 0;
  while(i <= len) {
    ptr = s + len - i;
    printf("ptr = %c\n",*ptr);
    if (*ptr >= 'a') {
      c = 10 + *ptr - 'a';
    }
    else {
      c = *ptr - '0';
    }
    res = res + c * exp(10,i);
    printf("res = %i, c= %i\n",res,c);
    i++;
  }
  return(res);
}


void PrintPack(struct _PACKET *p) {
  struct  in_addr addr;

  addr.s_addr = p->src_ip;
  printf("IP Source: %s\n",inet_ntoa(addr));
  addr.s_addr = p->dst_ip;
  printf("IP Destination: %s\n",inet_ntoa(addr));
  switch(p->proto) {
    case 1:
      printf("ICMP\n");
      return;
      break;
    case 6:
      printf("TCP\n");
      break;
    case 17:
      printf("UDP");
      break;
    default:
      break;
  }
  printf("Source Port: %u\n",p->src_prt);
  printf("Destination Port: %u\n",p->dst_prt);
  printf("IP ID: %u\nTCP Windows: %i\nTCP urg: %i\nProtocol %u\nTTL: %u\n",p->ip_id,p->win,p->urg,p->proto,p->ttl);
  printf("TCP Flags: %u\nTCP seq: %u\nTCP ack: %u\n",p->flags,p->seq,p->ack);
  /*if ((p->buffer) && (p->buf_size > 0))
    printf("%s\n",p->buffer);*/
  return;
}

void PrintPacket(u_char *packet) {
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const struct sniff_udp *udp;

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + size_ethernet);
  printf("IP Source: %s\n",inet_ntoa(ip->ip_src));
  printf("IP Destination: %s\n",inet_ntoa(ip->ip_dst));
  printf("IP Length: %u\n",ntohs(ip->ip_len));
  switch(ip->ip_p) {
    case 6:
      tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
      printf("TCP\n");
      printf("Source PORT: %u\n",ntohs(tcp->th_sport));
      printf("Destination PORT: %u\n",ntohs(tcp->th_dport));
      printf("Seq: %u\n",ntohl(tcp->th_seq));
      printf("Ack: %u\n",ntohl(tcp->th_ack));
      printf("Flags: 0x%x:",tcp->th_flags);
      if (tcp->th_flags & TH_SYN) 
        printf("SYN ");
      if (tcp->th_flags & TH_FIN)
        printf("FIN ");
      if (tcp->th_flags & TH_ACK)
        printf("ACK ");
      if (tcp->th_flags & TH_RST)
        printf("RESET ");
      printf("\n");
      if (ntohs(ip->ip_len) > size_ip + (tcp->th_off * 4))
        printf("%s\n",packet + size_ethernet + size_ip + (tcp->th_off * 4));
      break;
    case 17:
      udp = (struct sniff_udp*)(packet + size_ethernet + size_ip);
      printf("UDP\n");
      printf("Source PORT: %u\n",udp->uh_sport);
      printf("Destination PORT: %u\n",udp->uh_dport);
      break;
  }
}

size_t ReadBuffer(char *filename,u_char *buffer,size_t size,u_char convert) {
  FILE *my_file;
  size_t len,i,j;
  char ptr[size];

  my_file = fopen(filename,"rb");
  if (!my_file || my_file == -1) {
    printf("can't open file %s Error %i\n",filename,my_file);
    return 0;
  }
  len = fread(buffer,1,size,my_file);
  if (len > 0) {
    if (convert) {
      i = 0;
      j = 0;
      strncpy(ptr,buffer,len);
      while(i < len) {
        if (ptr[i] == '\n') {
           buffer[j++] = '\r';
           buffer[j++] = '\n';
        }
        else {
          buffer[j++] = ptr[i];
        }
        i++;
      }
      len = j;
    }
    return len;
  }
  else {
    return 0;
  }
}

size_t ReadHexBuffer(char *filename,unsigned char *out) {
  FILE *my_file;
  char *res;
  size_t len,index,count;
  unsigned char val;

  printf("Reading file %s and converting to hex code\n",filename);
  my_file = fopen(filename,"rb");
  if (!my_file) return 0;
  res = (char*)malloc(1524);
  len = fread(res,1,1524,my_file);
  if (len > 0) {
    index = 0;
    count = 0;
    printf("Converting to hexcode %i characters\n",len);
    while(count < len) {
      if ((res[count] == '\r') || (res[count] == '\n') || (res[count] == ' ')) {
        count++;
        continue;
      }
      val = 0;
      printf("%c %c\n",res[count],res[count + 1]);
      printf("%x %x\n",res[count],res[count + 1]);
      if ((res[count] >= 'a') && (res[count] <= 'z'))
         val = (res[count] - 'a' + 10) * 16;

      if ((res[count] >= 'A') && (res[count] <= 'Z'))
         val = (res[count] - 'A' + 10) * 16;

      if ((res[count + 1] >= 'a') && (res[count + 1] <= 'z'))
         val = val + 10 + res[count + 1] - 'a';

      if ((res[count + 1] >= 'A') && (res[count + 1] <= 'Z'))
         val = val + 10 + res[count + 1] - 'A';

      if ((res[count + 1] >= '0') && (res[count + 1] <= '9'))
         val = val + res[count + 1] - '0';

      if ((res[count] >= '0') && (res[count] <= '9'))
         val = val + ((res[count] - '0') * 16);

      /*printf("Debug val = %i\n",val);*/
      out[index] = val;
      /*printf("Debug val = %i hex = 0x%x/%i\n",val,out[index],out[index]);*/
      count += 2;
      index++;
    }
    printf("TEST %x %x %x\n",'A','a','0');
    printf("Converted %i characters\n",index);
    printf(".....0x%x 0x%x\n",out[0],out[1]);
    return index;
  }
  return len;
}

/*


          +------+   +-----+              +-----+
          |char**|-->|PTR0 |-------+ char*|     |
                     |PTR1 |-----+ |----->|char0|
                     |     |     |        |char1|
                                 |        
                                 |
                                 |        |charn|
                     |     |     |        +-----+
                     +-----+     |      
                                 +------->|char0|
*/

int ReadSrcFile(char **param,char *filename, int size) {
  int count,len,pos,i;
  FILE *my_file;
  char *buffer;
  char token[32];
  char *ptr;

  my_file = fopen(filename,"rb");
  if (!my_file || (my_file == -1)) {
    printf("Can't open file %s Error %i\n",filename,my_file);
    exit(0);
  }
  buffer = malloc(16001);
  if (!buffer) {
    printf("Malloc Error - can't allocate buffer to read file\n");
  }
  len = fread(buffer,1,16000,my_file); 

  printf("Read %i char from file %s\n",len,filename);
  count = 0;
  i = 0;
  pos = 0;
  while(i < len) {
    #ifdef READ_DEBUG
    printf("char %i: %c\n",i,buffer[i]);
    #endif
    if (pos < 0) {
      if (buffer[i] == '\n') 
        pos = 0;
      i++;
      continue;
    }
    if ((pos == 0) && (buffer[i]=='#')) {
      i++;
      pos = -1;
      /* skip commentary */
      continue;
    }
    if ((buffer[i] == ' ')||(buffer[i]=='\r')||(buffer[i]=='\n')||(buffer[i]=='\t')) {
      if (pos == 0) {
        i++;
        continue;
      }
     
      /*FOUND NEW token*/
      /* allocate memory and copy*/
      ptr = (char *)malloc(sizeof(char)*(pos + 1));
      if (!ptr) {
        printf("ERROR can't allocate memory for token\n");
        exit(0);
      }

      token[pos] = '\0';
      if (!strncpy(ptr,token,pos)) {
        printf("strncpy failed\n");
        exit(0);
      }
      #ifdef READ_DEBUG
      printf("token size : %i\n",pos);
      printf("Token: %s\n",ptr);
      #endif
      param[count++] = ptr;
      if (count > size) return count;
      /* reset variables */
      pos = 0;
      i++;
    }
    else {
      token[pos++] = buffer[i++];
    }        
  }
  printf("Read %i tokens\n",count);
  return(count);
}
