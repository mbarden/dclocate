#include <poll.h>
#include <netdb.h>
#include <ldap.h>
#include <lber.h>
#include <string.h>
#include "lsa_cldap.h"
#include "lsa_srv.h"
#include <stdio.h>
#include <errno.h>

DOMAIN_CONTROLLER_INFO *
dc_locate(const char *dname)
{

	lsa_cldap_t *lc;
	lsa_cldap_host_t *lch;
	lsa_srv_ctx_t *ctx;
	srv_rr_t *sr = NULL, *dc;
	BerElement *pdu = NULL, *ret = NULL;
	struct _berelement *be, *rbe;
 	DOMAIN_CONTROLLER_INFO *dci = NULL;
	int r, msgid;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *paddr = (struct sockaddr_in6 *)&addr;
	socklen_t addrlen;
	char *dcaddr = NULL, *dcname = NULL;

	ctx = lsa_srv_init();
	if (ctx == NULL)
		goto fail;

	r = lsa_srv_lookup(ctx, "_ldap._tcp.dc._msdcs", dname);
	printf("%d\n", r);
	if (r <= 0) 
		goto fail;


	/* print */
/*
	   lsa_srvlist_sort(ctx);*/
	/* error code? print */

	lc = lsa_cldap_init();

	if ((pdu = ber_alloc()) == NULL)
		goto fail;
	
	r = lsa_cldap_setup_pdu(pdu, dname, NULL, NETLOGON_NT_VERSION_5EX); /* is ntver right? */

	struct pollfd pingchk = {lc->lc_sock, POLLIN, 0};

	if ((dcaddr = malloc(INET6_ADDRSTRLEN + 2)) == NULL)
		goto fail;

	if ((dcname = malloc(MAXHOSTNAMELEN + 3)) == NULL)
		goto fail;

	be = (struct _berelement *)pdu;
	while((sr = lsa_srv_next(ctx, sr)) != NULL) {
		r = sendto(lc->lc_sock, be->ber_buf, (size_t)(be->ber_end - be->ber_buf),
		       0, (struct sockaddr *)&sr->addr, sizeof(sr->addr));
		printf("%d\n",r);
		if(poll(&pingchk, 1, 100) == 0)
			continue;
		if ((ret = ber_alloc()) == NULL)
			goto fail;
		
		rbe = (struct _berelement *)ret;
		recvfrom(lc->lc_sock, rbe->ber_buf, 
			 (size_t)(rbe->ber_end - rbe->ber_buf), 0, (struct sockaddr *)&addr, &addrlen);

		if ((dci = malloc(sizeof (DOMAIN_CONTROLLER_INFO))) == NULL) {
			ber_free(ret, 1);
			goto fail;
		}

		if ((r = lsa_cldap_parse(ret, dci)) == 0)
			break;
		ber_free(ret, 1);
		if (r > 1)
			goto fail;
	}

	if (sr == NULL)
	  goto fail;

	ber_free(pdu, 1);

	if(strncpy(dcaddr, "\\\\", 2) == NULL)
		goto fail;

	
	/*sr->addr isn't guaranteed to be correct - get it from elsewhere*/
	inet_ntop(paddr->sin6_family, &paddr->sin6_addr, dcaddr+2, INET6_ADDRSTRLEN);
	/*inet_ntop(sr->addr.sin6_family, &sr->addr.sin6_addr, dcaddr+2, INET6_ADDRSTRLEN);*/
	dci->DomainControllerAddress = dcaddr;
	dci->DomainControllerAddressType = DS_INET_ADDRESS;


	lsa_srv_fini(ctx);
	lsa_cldap_fini(lc);
	return (dci);

 fail:
	if (ctx)
		lsa_srv_fini(ctx);
	if (lc)
		lsa_cldap_fini(lc);
	if (dcaddr)
		free(dcaddr);
	if (dcname)
		free(dcname);
	if (pdu)
		ber_free(pdu, 1);

	return (NULL);
}
