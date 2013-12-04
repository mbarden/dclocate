#include <ldap.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <netdb.h>
#include "lsa_cldap.h"

int main(int argc, char *argv[]){


  DOMAIN_CONTROLLER_INFO *dci;
  int r;
  if ((dci = malloc(sizeof (DOMAIN_CONTROLLER_INFO))) == NULL) {
  
    return 1;
  }

  BerElement *ret = ber_alloc();
  struct _berelement *re = ret;
  char c = 0;
  int i = 0;

  char *rbe = re->ber_buf;
  while((c = getchar()) != EOF)
    rbe[i++] = c;
  dci->DomainControllerName = malloc(MAXHOSTNAMELEN + 3);
  r = lsa_cldap_parse(ret, dci);

  printf("%d\n",r);
  
  printf("DomainControllerName: %s\n", dci->DomainControllerName);
  printf("DomainControllerAddress: %s\n", dci->DomainControllerAddress);
  printf("DomainControllerAddressType: %l\n", dci->DomainControllerAddressType);
  printf("DomainGuid: ");
  printf("%x", *((unsigned int *)dci->DomainGuid));
  printf("-");
  for(i = 0; i < 2; i++) {
    printf("%x", *((unsigned short *)(dci->DomainGuid+4+2*i)) & 0xffff);
    printf("-");
  }
  int j;
  for(i = j = 8; i - j < 2; i++)
    printf("%x", *(dci->DomainGuid+i) & 0xff);
  printf("-");
  for(i = j = 10; i - j < 6; i++)
    printf("%x", *(dci->DomainGuid+i) & 0xff);
  printf("\n");
  printf("DomainName: %s\n", dci->DomainName);
  printf("DnsForestName: %s\n", dci->DnsForestName);
  printf("Flags: 0x%lx\n", dci->Flags);
  printf("DcSiteName: %s\n", dci->DcSiteName);
  printf("ClientSiteName: %s\n", dci->ClientSiteName);
  
  /*  
  in6_addr_t t;
  int i;
  unsigned int a;
  char c[4] = {0xcc, 0x98, 0xba, 0x33};
  char *cp = c;
  unsigned short *n = &t;
  char *p = &a;
  inet_pton(AF_INET6, "2001:4f8:0:2::13", &t);
  */
  /*  
  for(i = 0 ; i < 4 ; i++)
    printf("0x%x %x\n", cp+i, (c[i] & 0xff));
  NS_GET32(a, cp);
  */
  /*
  for(i = 0 ; i < 8 ; i++)
    printf("0x%x %x\n", n+i, (n[i]));
  */
  /*
  for(i = 0 ; i < 4 ; i++)
    printf("0x%x %x\n", p+i, (p[i] && 0xff));
  */

  return 0;
}
