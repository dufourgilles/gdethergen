
void do_child(libnet_ctx *ctx, struct _PACKET *pack,int packtot,
		int *pipes, char *filter_app,int semid) 
{
  int packid,i,j;
  pcap_t *handle;                        /* Session handle */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program filter;            /* The compiled filter */
  bpf_u_int32 mask;                     /* Our netmask */
  bpf_u_int32 net;                        /* Our IP */
  struct pcap_pkthdr header;          /* The header that pcap gives us */

  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const struct sniff_udp *udp;
  const char *payload; /* Packet payload */
  /* For readability, we'll make variables for the sizes of each of the structures
  int size_ethernet = sizeof(struct sniff_ethernet);
  int size_ip = sizeof(struct sniff_ip);
  int size_tcp = sizeof(struct sniff_tcp);*/
  char *addr,saddr[16],daddr[16];
  u_short off;
  u_char *packet;
  int transmit,len;
  struct in_addr in;
  struct sembuf sem_op;
  struct _PACKET *epac;
  char *dev;


  close(pipes[PIPE_READ]);

  /* Define the device */
  device = dev;
  printf("CHILD:device %s flag %i\n",ctx->device,ctx->flag);


  dev = ctx->device;
  if (dev == NULL)
    dev = pcap_lookupdev(errbuf);
  /* Find the properties for the device */
  pcap_lookupnet(dev, &net, &mask, errbuf);
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  /* Compile and apply the filter */
  pcap_compile(handle, &filter, filter_app, 0, net);
  pcap_setfilter(handle, &filter);
 


  if ((ctx->flag & ETHER_ENABLE) == 0) {
    printf("CHILD - ethernet not enable\n");
    ctx->device = NULL;
  }

 
  /* finally, signal the semaphore - increase its value by one. */
  printf("Received ready\n");
  sem_op.sem_num = 0;
  sem_op.sem_op = 1;  
  sem_op.sem_flg = 0;
  semop(semid, &sem_op, 1);

  packid = 0;
  transmit = 0;
  epac = NULL;
  while((packid <= packtot) && (pack[packid].gdipgen_type != GENTYPE_RECEIVE)) {
    packid++;
  }
  while((packid <= packtot)  && (pack[packid].gdipgen_type == GENTYPE_RECEIVE)) 
  {
    #ifdef DEBUG
    printf("Waiting for Packet id %i-%i\n",packid,packtot);
    #endif
    i = 1;
    do {
      packet = pcap_next(handle, &header);
      if (i && !packet) {
        printf("Packet received Error\n");
         i--;
      }
    }while(!packet);
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + size_ethernet);
    #ifdef DEBUG
      printf("Rec: %s",inet_ntoa(ip->ip_src));
      printf("->%s\n",inet_ntoa(ip->ip_dst));
    #endif
    if ((ip->ip_src.s_addr == pack[packid].src_ip) && (ip->ip_dst.s_addr == pack[packid].dst_ip) && (ip->ip_p == pack[packid].proto)) {
      switch(ip->ip_p) {
        case 6:
          tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
          if (((pack[packid].src_prt == 0) || 
               (pack[packid].src_prt == ntohs(tcp->th_sport))) &&
              ((pack[packid].dst_prt == 0) || 
               (pack[packid].dst_prt == ntohs(tcp->th_dport)))) 
          {
            if ((pack[packid].minlen < ntohs(ip->ip_len)) && 
                (pack[packid].flags == tcp->th_flags)) 
            {
              transmit = 1;
            }
            else {
              printf("Incorrect Flags or Length\n");
              printf("Length: %u <> min %u\n",ntohs(ip->ip_len),pack[packid].minlen);
              printf("Flags: %x <> %x\n",tcp->th_flags,pack[packid].flags);
	      transmit = 0;
            }
          }
          else 
            printf("SRC %i | %i : DST %i | %i\n",pack[packid].src_prt, ntohs(tcp->th_sport),pack[packid].dst_prt,ntohs(tcp->th_dport));
          break;
        case 17:
          udp = (struct sniff_udp*)(packet + size_ethernet + size_ip);
	  printf("UDP %u-%u %u-%u\n",pack[packid].src_prt,ntohs(udp->uh_sport),pack[packid].dst_prt,ntohs(udp->uh_dport));
          if (((pack[packid].src_prt == 0) ||
               (pack[packid].src_prt == ntohs(udp->uh_sport))) &&
              ((pack[packid].dst_prt == 0) ||
               (pack[packid].dst_prt == ntohs(udp->uh_dport))))
            transmit = 1;
          break;
        default:
          break;
      } /* switch(ip->ip_p) */ 
      if (transmit) {
        if (pack[packid].icmp_code > 0) {
      /*we have to send an icmp unreachable as a result of receiving this pack*/
          printf("Creating UNCREACH PACKET %u\n",ntohs(ip->ip_len)); 
	  transmit = ntohs(ip->ip_len) - size_ip;
	  if (transmit <= 0 ) {
	     printf("CHILD: epac len is <= 0\n");
	  }
	  else {
            epac = (struct _PACKET *)malloc(sizeof(struct _PACKET) + 
			ntohs(ip->ip_len) - size_ip);
            epac->src_ip = ip->ip_src.s_addr;
            epac->dst_ip = ip->ip_dst.s_addr;
            epac->ip_id = ntohs(ip->ip_id);
            epac->tos = ip->ip_tos;
            epac->ip_len = ntohs(ip->ip_len);
            epac->frag = ntohs(ip->ip_off);
            epac->ttl = ip->ip_ttl;
            epac->proto = ip->ip_p;
            epac->buf_size = epac->ip_len - size_ip;
            if (epac->buf_size <= 0) {
		printf("ICMP UNREACH - Error buf_size is %i\n",epac->buf_size);
		epac->buf_size = 0;
		epac->buffer = NULL;
	    }
            else {
  		epac->buffer = (u_char*)(epac + 1);
          	memcpy(epac->buffer,packet + size_ethernet + size_ip, epac->buf_size);
	    }
	 }
         
           
	  printf("UNREACH PACKET Created\n");
        }

        /* find the next packet to receive */
        do
        {
          /*packid++;*/
          if ((pack[packid].topacket > 0)&&(pack[packid].count > 0)) {
            i = pack[packid].topacket - 1;
	    pack[packid].count--;
            printf("CHILD: goto function from %i to %ii with count %i\n",
			packid,i,pack[packid].count);
            j = i;
            while( j <= packid) {
              if (pack[j].gdipgen_type == GENTYPE_RECEIVE) {
                if (pack[packid].inc ) {
                  switch(pack[packid].inctype) {
                    case INC_TYPE_IP_DST:
                        pack[j].src_ip = ntohl(htonl(pack[j].src_ip) + 
					pack[packid].inc);
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                    case INC_TYPE_IP_SRC:
                        pack[j].dst_ip =  ntohl(htonl(pack[j].dst_ip) + 
					pack[packid].inc);
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                    case INC_TYPE_TCP_DST:
                        pack[j].src_prt += pack[packid].inc;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                    case INC_TYPE_TCP_SRC:
                        pack[j].dst_prt += pack[packid].inc;
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        break;
                  } /* switch(pack[packid].inctype) */
                } /* if (pack[packid].inc ) */
                else {
                  pack[j].src_prt = pack[j].cfg_src_prt;
                  pack[j].dst_prt = pack[j].cfg_dst_prt;
                }
              } /*  if (pack[j].gdipgen_type == GENTYPE_RECEIVE) */
              pack[j].seq = pack[j].cfg_seq;
              pack[j].ack = pack[j].cfg_ack;
              j++;
            }
            packid = i;
          }
          else {
            packid++;
          }
        } while((packid <= packtot) && (pack[packid].gdipgen_type != GENTYPE_RECEIVE));

        len = size_ethernet + ntohs(ip->ip_len);
        if (len > 1550)
          len = 1550;
        transmit = write(pipes[PIPE_WRITE],&len,sizeof(int));
        if (transmit <= 0) {
	  printf("Error: Child transmit error\n");
        }
        transmit = write(pipes[PIPE_WRITE],packet,len);
	printf("CHILD: Sent %u bytes to parent process\n",transmit);
        printf("CHILD Packet\n");
	PrintPacket(packet);
        if (epac) {
          len = sizeof(struct _PACKET) + epac->buf_size;
	  transmit = write(pipes[PIPE_WRITE],&len,sizeof(int));
          transmit = write(pipes[PIPE_WRITE],epac,len);
	  printf("CHILD sent ICMP info %i\n",transmit);
	  free(epac);
	  epac = NULL;
	}

        transmit = 0;

        if (packid > packtot)
          break;

        /* To avoid submitting the ports for every packets
           reuse the previous ones if nothing specified
         */
        if ((pack[packid].src_prt == 0) && (pack[packid].dst_prt == 0)) 
        {
           pack[packid].src_prt = ntohs(tcp->th_sport);
           pack[packid].dst_prt = ntohs(tcp->th_dport);
        }
      } /* if (transmit) */
    } /* if (SAME IP) */
  } /*enf of while(packid < packtot) */  
  /* And close the session */
  pcap_close(handle);
  close(pipes[PIPE_WRITE]);
  return;
}
