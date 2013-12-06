#include "dc_locate.h"
#include "lsa_srv.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <inttypes.h>

void 
lsa_srv_output(lsa_srv_ctx_t *ctx)
{
	srv_rr_t *sr = NULL;
	char buf[INET6_ADDRSTRLEN];


	while ((sr = lsa_srv_next(ctx, sr)) != NULL) {
		inet_ntop(sr->addr.sin6_family, &sr->addr.sin6_addr, buf, 
			  INET6_ADDRSTRLEN);
		printf("target %s:%" PRIu16
		    ", pri %" PRIu16 ", weight %" PRIu16 " addr %s\n",
		       sr->sr_name, sr->sr_port, sr->sr_priority, sr->sr_weight,
		       buf);
	}
	printf("\n");
}

int main(int argc, char *argv[]) {
  	DOMAIN_CONTROLLER_INFO *dci;
	int i;
	
	if (argc < 3) {
		printf("usage: ./a.out prefix dname\n");
		return 0;
	}
	
	dci = dc_locate(argv[1], argv[2]);
	
	if (dci != NULL) {
		printf("DomainControllerName: %s\n", dci->DomainControllerName);
		printf("DomainControllerAddress: %s\n", dci->DomainControllerAddress);
		printf("DomainControllerAddressType: %d\n", dci->DomainControllerAddressType);
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
	freedci(dci);
	return 0;
}
 
