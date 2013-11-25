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
  printf("DomainGuid: %lx%lx\n", *(unsigned long *)dci->DomainGuid,
	 *(unsigned long *)dci->DomainGuid+8);
  printf("DomainName: %s\n", dci->DomainName);
  printf("DnsForestName: %s\n", dci->DomainControllerName);
  printf("Flags: 0x%lx\n", dci->Flags);
  printf("DcSiteName: %s\n", dci->DcSiteName);
  printf("ClientSiteName: %s\n", dci->ClientSiteName);
  }
  return 0;
}
