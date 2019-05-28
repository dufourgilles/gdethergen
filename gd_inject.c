
/****************************************************
 *        ICMP PACKET INJECTOR
 ****************************************************/
#define DEBUG 1



void GenerateData(char *buffer, int size, char addhttpend)
{
  int i;
  if (!buffer) {
    printf("Incorrect Buffer\n");
  }
  #ifdef DEBUG 
  printf("Generating data - size %i - http end %i\n",size,(int)addhttpend);
  #endif
  if (addhttpend) {
    size -= 4;
  }
  i = 0;
  while(i < size) {
    buffer[i++] = 'a';
  }
  if (addhttpend) {
    buffer[i] = '\r';
    buffer[i+1] = '\n';
    buffer[i+2] = '\r';
    buffer[i+3] = '\n';
  }
  #ifdef DEBUG 
  printf("Data: %s<->\n",buffer);
  #endif
  return;
}


#ifdef LIBNET_IPV4_H
  #include "gd_inject_new_lib.c"
#else
  #include "gd_inject_old_lib.c"
#endif