
void do_parent(libnet_ctx *ctx,  
		struct _PACKET *pack,int packtot,
		int *pipes,int semid) 
{
  int packid,child_len;
  u_char packet[1600];
  size_t len;
  struct sembuf sem_op;
  char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */  
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  u_long topacket,quantity,repeat;
  int next,i,j,inc;
  u_char fast_mode;
  struct _PACKET *epac;

  
  fast_mode = ctx->flag & FAST_MODE; 
  
  printf("fast mode %i\n",fast_mode);
  
  close(pipes[PIPE_WRITE]);
  printf("PARENT running\n");
  packid = 0;
  while(packid <= packtot) {
    if (fast_mode == 0)
      printf("Packet %i - type %i\n",packid,pack[packid].gdipgen_type);
    else {
      printf("Packet %i\r",packid);
    }
    if (pack[packid].gdipgen_type == GENTYPE_SEND) {
    /* packet to send*/
      quantity = pack[packid].quantity;
      repeat = pack[packid].repeat;
      if (fast_mode == 0) {
        printf("Sending packet %i with %i every %i over a period of %i\n",packid,quantity,pack[packid].delay,repeat);
        PrintPack(&pack[packid]);
        printf("My Frag: %u - %u\n",pack[packid].frag,pack[packid].frag  & IP_OFFMASK );
      }
      if ((pack[packid].frag  & IP_OFFMASK) > 0) {
     /* ip fragments - don't use tcp or udp injector */
        if (fast_mode == 0) 
          printf("Sending Fragments - calling IPInject\n");
        IPInject(&pack[packid],ctx);
      }
      else {
        switch(pack[packid].proto ) {
        case 0: /* ARP */
          ARPInject(&pack[packid],ctx);
	   break;
        case 1:
          /* ICMP unreachable in response to the last packet received */
	  len = read(pipes[PIPE_READ],&child_len,sizeof(int));
	  if (len < sizeof(int)) {
	    printf("PARENT: error reading int\n");
          }
	  epac = (struct _PACKET*)malloc(child_len);
	  len = read(pipes[PIPE_READ],epac,child_len);	  
	  if (len) {
	    epac->buffer = (u_char*)(epac + 1);
	    /*epac->buf_size = len - sizeof(struct _PACKET);*/
            if (fast_mode == 0)
            {
	      PrintPack(epac);
	      printf("Epac buf_size %u\n",epac->buf_size);
	    } 
	    pack[packid].packet = epac;
            ICMPInject(&pack[packid],ctx);
	    free(epac);
 	  }
	  else {
	    printf("Warning: ICMP Packet len %i\n",len);
	  }
          break;
        case 6:
          while(repeat) {
            quantity = pack[packid].quantity;
            while(quantity) {
              /*printf("calling tcpinject\n");*/
              tcpinject(&pack[packid],ctx);
              quantity--;
            } /*while(quantity)*/
            repeat--;
          } /*while(repeat)*/
          break;
        case 17:
          while(repeat) {
            quantity = pack[packid].quantity;
            while(quantity) {
              udpinject(&pack[packid],ctx);
              quantity--;
            }
            repeat--;
            if (fast_mode == 0)
              printf("UDP repeat %i\n",repeat);
          }
          break;
        default:
          printf("Warning - protocol not supported\n");
          printf("Attempting IPInject\n");
          while(repeat) {
            quantity = pack[packid].quantity;
            while(quantity) {
              IPInject(&pack[packid],ctx);
              quantity--;
            }
            repeat--;
            if (fast_mode == 0)
              printf("IP repeat %i\n",repeat);
          }

          break;
        }
      } /* else */
      if (fast_mode == 0) {
        printf("Sent\n=====\n");
      }  
      if (pack[packid].delay) {
        printf("\nSleeping %i sec\n",pack[packid].delay);
        sleep(pack[packid].delay);
      }
      
      if ((pack[packid].topacket > 0) && (pack[packid].count > 0)) {
        i = pack[packid].topacket - 1;
	inc = pack[packid].inc;
        pack[packid].count-- ;
        if (fast_mode == 0)
          printf("PARENT2: goto function from %i to %i with count %i\n",packid,i,
			pack[packid].count);
        j = i;
        while( j <= packid) {
          if (pack[j].gdipgen_type == GENTYPE_SEND) {
            if (pack[packid].inc ) {
              switch(pack[packid].inctype) {
	        case INC_TYPE_IP_SRC:
			pack[j].src_ip = ntohl(htonl(pack[j].src_ip) + 
					pack[packid].inc);
			pack[j].src_prt = pack[j].cfg_src_prt;
			pack[j].dst_prt = pack[j].cfg_dst_prt;
			break;
		case INC_TYPE_IP_DST:
			pack[j].dst_ip = ntohl(htonl(pack[j].dst_ip) + 
					pack[packid].inc);
			pack[j].src_prt = pack[j].cfg_src_prt;
			pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                case INC_TYPE_TCP_SRC:
              		pack[j].src_prt += pack[packid].inc;
			pack[j].dst_prt = pack[j].cfg_dst_prt;
			/* printf("PARENT: increasing source port to %u\n",pack[j].src_prt); */
			break;
		case INC_TYPE_TCP_DST:
			pack[j].dst_prt += pack[packid].inc;	
			pack[j].src_prt = pack[j].cfg_src_prt;
                        break;
	      }
              pack[j].seq = pack[j].cfg_seq;
              pack[j].ack = pack[j].cfg_ack;
            }
            else {
	      /* printf("PARENT: inc is null\n"); */
              pack[j].src_prt = pack[j].cfg_src_prt;
	      pack[j].dst_prt = pack[j].cfg_dst_prt;
            }
          }
          j++;
        }
        if (pack[packid].next > 0) {
          next = pack[packid].next;
          printf("Setting next packet info for %i (%i)\n",next,i);
          if (pack[next].gdipgen_type == GENTYPE_SEND) {
            if (pack[next].cfg_seq == 0)
              pack[next].seq = pack[packid].seq + pack[packid].buf_size;
	    else 
              pack[next].seq = pack[next].cfg_seq;
            if (pack[next].cfg_ack == 0)
              pack[next].ack = pack[packid].ack;
	    else
	      pack[next].ack = pack[next].cfg_ack;
          }
        }
        packid = i;
      } /* end (pack[packid].topacket > 0) */
      else {
      /***************************************
       * copy seq/ack info into next packet  *
       ***************************************/
     
        if (pack[packid].next > 0) {
	  printf("Setting next packet info\n");
          next = pack[packid].next;
          if (pack[next].gdipgen_type == GENTYPE_SEND) {
            if (pack[next].seq == 0)
              pack[next].seq = pack[packid].seq + pack[packid].buf_size;
            if (pack[next].ack == 0) 
              pack[next].ack = pack[packid].ack;
          }
        }
        packid++;
     
        if (packid <= packtot) { 
          printf("Adjusting port info\n");
          if (pack[packid].gdipgen_type == GENTYPE_SEND) {
            if (pack[packid].src_prt == 0)
              pack[packid].src_prt =  pack[packid - 1].src_prt;
            if (pack[packid].dst_prt == 0)
              pack[packid].dst_prt =  pack[packid - 1].dst_prt;
            if (pack[packid].src_ip == 0)
              pack[packid].src_ip = pack[packid - 1].src_ip;
            if (pack[packid].dst_ip == 0)
              pack[packid].dst_ip = pack[packid - 1].dst_ip;  
          }
        }
      } /* else */
    } /* if (pack[packid].gdipgen_type == GENTYPE_SEND) */
    else {
      /* receive */
      /*sem_op.sem_num = 0;
      sem_op.sem_op = -1;
      sem_op.sem_flg = 0;
      if (fast_mode == 0)
        printf("Waiting for packet ...\n");
      semop(semid, &sem_op, 1);
      */
      i = 0;
      do {
        len = read(pipes[PIPE_READ],&child_len,sizeof(int));
        if ((!i) && (len <= 0))  {
          printf("Error: parent got a null msg\n");
          i++;
        }
        if (child_len > 0) 
          len = read(pipes[PIPE_READ],packet,child_len);
      }while(len <= 0);
      if (len > 0) {
        printf("Received len %i\n",len);
        len = 0;
        if (fast_mode == 0) 
        {
          printf("Received\n---------\n");
          PrintPacket(packet);
          printf("\n----------------------------\n");
        }
        if (pack[packid].delay) {
          printf("Sleeping %i\n",pack[packid].delay);
          sleep(pack[packid].delay);
        }
        ip = (struct sniff_ip*)(packet + size_ethernet);
        tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);

        /***************************************
         * copy seq/ack info into next packet  *
         ***************************************/

        if ((pack[packid].topacket > 0) && (pack[packid].count > 0)) {
          i = pack[packid].topacket - 1;
	  pack[packid].count--;
          if (fast_mode == 0)
            printf("PARENT1: goto function from %i to %i with count %i\n",i,packid,
		pack[packid].count);
          j = i;
          while( j <= packid) {
            if (pack[j].gdipgen_type == GENTYPE_SEND) {
              if (pack[j].inc ) {
                switch(pack[j].inctype) {
                  case INC_TYPE_IP_SRC:
                        pack[j].src_ip = ntohl(htonl(pack[j].src_ip) + pack[j].inc);
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                  case INC_TYPE_IP_DST:
                        pack[j].dst_ip = ntohl(htonl(pack[j].dst_ip) + pack[j].inc);
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                  case INC_TYPE_TCP_SRC:
                        pack[j].src_prt += pack[j].inc;
                        pack[j].dst_prt = pack[j].cfg_dst_prt;
                        break;
                  case INC_TYPE_TCP_DST:
                        pack[j].dst_prt += pack[j].inc;
                        pack[j].src_prt = pack[j].cfg_src_prt;
                        break;
                } 
              } /*  if (pack[j].inc ) */
              else {
                pack[j].src_prt = pack[j].cfg_src_prt;
		pack[j].dst_prt = pack[j].cfg_dst_prt;
              }
              pack[j].seq = pack[j].cfg_seq;
              pack[j].ack = pack[j].cfg_ack;
            }
            j++;
          }
          packid = i;
          if (pack[packid].seq == 0)
            pack[packid].seq = ntohl(tcp->th_ack);
          if (pack[packid].ack == 0) {
            pack[packid].ack = ntohl(tcp->th_seq) + ntohs(ip->ip_len) -
                               size_ip  - (tcp->th_off * 4);
            if ((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN))
              pack[packid].ack++;
          }
        } /* end (pack[packid].topacket > 0) */

        else {
          if (pack[packid].next > 0) {
            next = pack[packid].next;
            if (pack[next].gdipgen_type == GENTYPE_SEND) {
              if (pack[next].cfg_seq == 0)
                pack[next].seq = ntohl(tcp->th_ack);
              else 
	        pack[next].seq = pack[next].cfg_seq;
              if (pack[next].cfg_ack == 0) {
                pack[next].ack = ntohl(tcp->th_seq) + ntohs(ip->ip_len) - size_ip - (tcp->th_off * 4);
                if ((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN))
                  pack[next].ack++;
              }
	      else {
                pack[next].ack = pack[next].cfg_ack;
	      }
            }
          } /* if (pack[packid].next > 0) */
          packid++;
          if (packid <= packtot) {
            if (pack[packid].gdipgen_type == GENTYPE_SEND) {
              if (pack[packid].src_prt == 0)
                pack[packid].src_prt = ntohs(tcp->th_dport);
              if (pack[packid].dst_prt == 0)
                pack[packid].dst_prt = ntohs(tcp->th_sport);
              if (pack[packid].src_ip == 0)
                pack[packid].src_ip = pack[packid - 1].dst_ip;
              if (pack[packid].dst_ip == 0)
                pack[packid].dst_ip = pack[packid - 1].src_ip;
            }
          }/* if (pack[packid].gdipgen_type == 1) */
        } /* else */
      } /* if (len) */
    } /* else */
  } /*while*/
  printf("All packets sent\n");
  if (device) {
    if (libnet_close_link_interface(network) == -1)
    {
        libnet_error(LN_ERR_WARNING, "libnet_close_link_interface couldn't close the interface");
    }
  } 
  else {
    printf("\n\nClosing Libnet\n\n");
    libnet_close_raw_sock(sock);
  }
  
  close(pipes[PIPE_READ]);
  return;
}
	      
