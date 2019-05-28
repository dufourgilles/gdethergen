void PrintPack(struct _PACKET *p);
void PrintPacket(u_char *packet);
size_t ReadBuffer(char *filename,u_char *buffer,size_t size,u_char convert);
size_t ReadHexBuffer(char *filename,unsigned char *out);
int ReadSrcFile(char **param,char *filename, int size);
int exp(int a, int b);
int atoh(char *s);
