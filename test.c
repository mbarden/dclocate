#include <resolv.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdio.h>

int main(int argc, char *argv[]){
  
  in6_addr_t t;
  int i;
  unsigned int a;
  char c[4] = {0xcc, 0x98, 0xba, 0x33};
  char *cp = c;
  unsigned short *n = &t;
  char *p = &a;
  inet_pton(AF_INET6, "2001:4f8:0:2::13", &t);

  /*  
  for(i = 0 ; i < 4 ; i++)
    printf("0x%x %x\n", cp+i, (c[i] & 0xff));
  NS_GET32(a, cp);
  */
  for(i = 0 ; i < 8 ; i++)
    printf("0x%x %x\n", n+i, (n[i]));

  /*
  for(i = 0 ; i < 4 ; i++)
    printf("0x%x %x\n", p+i, (p[i] && 0xff));
  */

  return 0;
}
