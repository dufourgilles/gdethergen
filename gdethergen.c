
/*#######################################################
#
#          gdipgen.c
#
#   To Compile: 
#   cc `libnet-config --defines` -o gdethergen gdethergen.c `libnet-config --libs` -lpcap 
#
#   $AUTHOR: gdufour@cisco.com
#   $VERSION: 1.3.1
#   $DATE:   NOV-30-2004
#   $UPDATE: MAY-12-2005
#            - fixed bug in do_child waiting for a last unexisting packet.
#            FEB-09-2006
#	     - created the goto packet function
#            MAR-01-2006
#            - gotonext - same as goto but increment src port by 1
#	     APR-17-2006
#	     - Added TCP OPTIN Support
#	     MAY-11-2006
#	     - tcpopt bug - missing return after reading the token
#	     - goto bug - do not increase the src port
#            - libnet-init-packet bug - replace the libet init and destroy with
#              regular malloc/free due to seg fault
#	     - fixed the goto seq number problem
#	     JULY-27-2006
#	     - created icmp unreachable functionality
#	     AUG-13-2006
# 	     - created makefiles and splitted src code in multiple files
#	     - created gototype function
#	     SEPT-15-2006
#	     - fixed the icmp_unreach code
#	     OCT-13-2006
#	     - fixed the TCP Seq/Ack code when using -goto option
#	     MAY-02-2007
#	     - function to generate payload data
#	     OCT-07-2007
#	     - arptype function to generate arp packets
#	     - cleaned the printf command to reduce the output in fastmode 
######################################################
*/

#define MAX_IPOPTLEN 40
#define _SVID_SOURCE

#include <pcap.h>
#include <libnet.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sem.h>

#include "gdethergen.h"
#include "gd_packet.h"
#include "gd_util.h"
#include "gd_inject.h"

#include "gd_inject.c"
#include "gd_parent.c"
#include "gd_child.c"


void PrintHelp()
{
  printf("\t\t gdethergen %s\n\n",VERSION);
  printf("\t\t============\n\n");
  printf("by Gilles Dufour (gdufour@cisco.com)\n\n");
  printf("gdethergen <cfg_file> [<interface>] [-ether] [-fast]\n");
  printf("-ether: enable the use of ethernet mac addresses\n");

  printf("The <cfg_file> is a list of packets describing what packet to send\n");
  printf("and what packet to wait for.\n");
  printf("Each new packet start with -newsend if this is a packet to send or\n");
  printf("-newrcv if this is a packet to wait for.\n");
  printf("The packet requires at least a source and destination ip.\n");
  printf("If no source/destination port is provided, the tool will copy the info\n");
  printf("from the previous packet.\n\n");
  /*printf("A value of zero means any port.\n\n");*/

  printf("List of commands for the cfg_file\n");
  printf("-newsend: create a new send packet\n");
  printf("-newrcv: create a new receive packet\n");
  printf("-server: reverse the order of send/receive\n");
  printf("-icmp_code <code>: Send an icmp unreachable message upon receiving a packet.\n");
  printf("\t\t<code> should be the icmp code\n\t\tUnreach Net = 0\n\t\tUnreach Host = 1\n");
  printf("\t\tUnreach Proto = 2\n\t\tUnreach Port = 3...\n");
  printf("-count: decrement each time a goto function is called and stop when null\n");
  printf("-ipsrc <x.x.x.x>: Source IP address\n");
  printf("-ipdst <x.x.x.x>: Destination IP address\n");
  printf("-ethsrc <x:x:x:x:x:x>: Source MAC Address\n");
  printf("-ethdst <x:x:x:x:x:x>: Destination MAC address\n");
  printf("-portsrc <port>: Source Port\n");
  printf("-portdst <port>: Destination Port\n");
  printf("-ipid <ipid#>: IP ID\n");
  printf("-frag <frag#>: fragments bits and offset\n");
  printf("-df: Set don't fragment bit\n");
  printf("-mf: Set more fragmentd bit\n");
  printf("-offset: Set fragment offset\n");
  printf("-ttl <ttl#>: ttl bits\n");
  printf("-tos <tos#>: TOS bits\n");
  printf("-proto <proto#>: protocol number - default is 6\n");
  printf("-tcpopt: consider the payload as tcp option\n");
  printf("-TFIN: Set FIN flag\n");
  printf("-TSYN: Set SYN flag\n");
  printf("-TRST: Set RESET flag\n");
  printf("-TACK: Set ACK flag\n");
  printf("-TPUSH: Set push flag\n");
  printf("-win <size>: TCP window size\n");
  printf("-payload <file>: specify payload to attach at the end of the packet\n");
  printf("-header <file>: read file and convert every \\n into a \\r\\n\n");
  printf("-hex <file>: read file and assume it contains hex numbers\n");
  printf("-delay <sec>: introduce a delay in seconds after sending the current packet and\n\t\t");
  printf("before proceeding to the next packet\n");
  printf("-quantity <count>: how much packet to send with no delay\n");
  printf("-repeat <count>: send the packet x times and wait for <delay> between each packet\n");
  printf("-minlen <len>: only match packets with a length greater than minlen\n");
  printf("-gotonext <packet # counting from 1>: go to packet number X and adjust parameters\n");
  printf("-gototype <type>: works with gotonext.  Define which parameter to increase at each step.\n");
  printf("\t%i - IP Source\n\t%i - IP Destination\n\t%i - TCP Source\n\t%i - TCP Destination\n",INC_TYPE_IP_SRC, INC_TYPE_IP_DST, INC_TYPE_TCP_SRC, INC_TYPE_TCP_DST);
  printf("-goto <packet # counting from 1>: go to packet number #. No adjustments.  Same packets will be sent.\n");
  printf("-seq <seq#>: sequence number\n");
  printf("-ack <ack#>: ack number\n");
  printf("-crc <crc>: override the CRC for UDP/TCP\n");
  printf("-ipcrc <crc>: override the IP header checksum\n");
  printf("-arptype <1-6>: Send ARP messages\n\t1 -> Request\n\t2 -> Reply\n");
}

int main(int argc, char **argv)
{
  char filter_app[] = "host 192.168.111.246";       /* The filter expression */
  struct pcap_pkthdr header;          /* The header that pcap gives us */
  const u_char *packet;                 /* The actual packet */
  struct _PACKET pack[MAX_PACKET];
  struct in_addr in;
  int packid,type,i,mode;
  char *param[MAX_TOKEN];
  int pipes[2],pid;
  /* ID of the semaphore set.     */
  int sem_set_id_1; 
  struct sembuf sem_op;
  union semun sem_val;
  int j;
  libnet_ctx ctx;

  packid = 0;
  if (argc < 2) {
     PrintHelp();
    exit(0);
  }

  ctx.device = NULL;
  ctx.flag = 0;
  ctx.fast_mode = 0;

  if (argc > 1) 
    ctx.device = argv[2];
  if (argc > 2) {
    if (argv[3]) {
      if (strcmp(argv[3],"-ether")==0) 
      {
        printf("Ethernet mode on\n");
        ctx.flag |= ETHER_ENABLE;
        if ((argc > 3) && (argv[4]) && (strcmp(argv[4],"-fast")==0))
	  ctx.flag |= FAST_MODE;
      }
      else if (strcmp(argv[3],"-fast")==0) 
      {
        printf("Fast mode on - printing off\n");
        ctx.flag |= FAST_MODE;
      }
    }
  }

 
  if (argc = ReadSrcFile(param,argv[1],MAX_TOKEN))
	InitPack(&pack[packid]);
  i = 0;
  
  

  printf("Processing tokens\n");
  /****** First token should be SEND or RECEIVE  or SERVER*****/
  type = SetPack(&pack[packid],(void**)param,&i);
  if (type == GENTYPE_SERVER) {
    printf("Server mode\n");
    mode = GENTYPE_SERVER;
    type = SetPack(&pack[packid],(void**)param,&i);
  }
  else 
    mode = GENTYPE_CLIENT;
  pack[packid].gdipgen_type = SetType(type,mode);
  while(i < argc) {
    printf("Token %i\n",i);
    if (type = SetPack(&pack[packid],(void**)param,&i)) {
      /***************************************************
       *  find the previous packet with same ports and link it
       *  to this packet.  This will be used to set seq/ack
       *  later
       ****************************************************/
       j = packid - 1;
       while(j >= 0) {
         if ((pack[j].proto == 6) && 
            (((pack[j].src_prt == pack[packid].src_prt) && 
              (pack[j].dst_prt == pack[packid].dst_prt)) || 
              ((pack[j].src_prt == pack[packid].dst_prt) && 
              (pack[j].dst_prt == pack[packid].src_prt)))) {
          pack[j].next = packid;
          pack[packid].prev = j;
          break;
        }
        j--;
      }
      packid++;
      if (packid > MAX_PACKET) break;
      InitPack(&pack[packid]);
      pack[packid].packet_id = packid;
      pack[packid].gdipgen_type = SetType(type,mode);
      /*printf("New packet - %i\n",packid+1);*/
    }
  }
  j = packid - 1;
  while(j >= 0) {
     if ((pack[j].proto == 6) &&
         (((pack[j].src_prt == pack[packid].src_prt) &&
          (pack[j].dst_prt == pack[packid].dst_prt)) ||
          ((pack[j].src_prt == pack[packid].dst_prt) &&
           (pack[j].dst_prt == pack[packid].src_prt)))) {
        pack[j].next = packid;
        pack[packid].prev = j;
        break;
     }
     j--;
  }
  printf("Total Packet: %i\n",packid + 1);
  in.s_addr = pack[0].src_ip;
  sprintf(filter_app,"host %s",inet_ntoa(in));
  printf("Filtering on %s\n",filter_app);

  i = pipe(pipes);
  if (i == -1) {
    printf("Pipe Error\n");
    exit(1);
  }
  
  sem_set_id_1 = semget(SEM_ID, 1, IPC_CREAT | 0600);
  /* intialize the first (and single) semaphore in our set to '1'. */
  sem_val.val = 0;
  /* initialize the first semaphore in our set to '3'.  */
  i = semctl(sem_set_id_1, 0, SETVAL, sem_val);

/***********************
 * Libnet Init
 ***********************/
  InitCtx(&ctx);


  printf("Creating Process\n");
  pid = fork();
  switch(pid) {
    case -1:
      printf("Fork Error\n");
      exit(2);
    case 0:
/* child process */
      do_child(&ctx,pack,packid,pipes,filter_app,sem_set_id_1);
      exit(0);
    default:
       /* wait on the semaphore, unless it's value is non-negative. */
      sem_op.sem_num = 0;
      sem_op.sem_op = -1;   
      sem_op.sem_flg = 0;
      semop(sem_set_id_1, &sem_op, 1);
      printf("Starting Sender\n");
      if ((ctx.flag & ETHER_ENABLE) == 0) 
        ctx.device = NULL;
      else 
        printf("device %s flag %i\n",ctx.device,ctx.flag);
     
      do_parent(&ctx,pack,packid,pipes,sem_set_id_1);
      i = 0;
      while(i < packid) {
        DestroyPacket(&pack[i++]);
      }
      break;
  }
  
  exit(0);
}
