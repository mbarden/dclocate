#include "dc_locate.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  DOMAIN_CONTROLLER_INFO *dci;

  if (argc < 2) {
    printf("usage: ./a.out dname\n");
    return 0;
  }

  dci = dc_locate(argv[1]);
  if (dci != NULL) {
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
  }
  return 0;
}
