#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>
#include <ldap.h>
#include <lber.h>
#include <string.h>
#include <sys/socket.h>
#include "lsa_cldap.h"
#include "lsa_srv.h"

static int
lsa_bind()
{
        int                        fd;
        struct sockaddr_in6         addr;

        if ((fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
                return (fd);
        /*
         * Bind to all available addresses and any port.
         */
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = 0;

        if (bind(fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
                goto fail;

        return (fd);
fail:
        (void) close(fd);

        return (-1);
}

void
lsa_srv_output(lsa_srv_ctx_t *ctx) __attribute__((weak));

DOMAIN_CONTROLLER_INFO *
dc_locate(const char *prefix, const char *dname)
{
	lsa_srv_ctx_t *ctx;
	srv_rr_t *sr;
	BerElement *pdu = NULL, *ret;
	struct _berelement *be, *rbe;
 	DOMAIN_CONTROLLER_INFO *dci = NULL;
	int r, fd = -1;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *paddr;
	socklen_t addrlen;
	char *dcaddr = NULL, *dcname = NULL;

	ctx = lsa_srv_init();
	if (ctx == NULL)
		goto fail;

	r = lsa_srv_lookup(ctx, prefix, dname);
	if (r <= 0) 
		goto fail;

	if (lsa_srv_output)
		lsa_srv_output(ctx);

	if ((fd = lsa_bind()) < 0)
		goto fail;

	if ((pdu = ber_alloc()) == NULL)
		goto fail;
	
	/* 
	 * Is ntver right? It certainly works on w2k8... If others are needed,
	 * that might require changes to lsa_cldap_parse
	 */
	r = lsa_cldap_setup_pdu(pdu, dname, NULL, NETLOGON_NT_VERSION_5EX); 

	struct pollfd pingchk = {fd, POLLIN, 0};

	if ((dcaddr = malloc(INET6_ADDRSTRLEN + 2)) == NULL)
		goto fail;
	if (strncpy(dcaddr, "\\\\", 3) == NULL)
		goto fail;
	if ((dcname = malloc(MAXHOSTNAMELEN + 3)) == NULL)
		goto fail;

	be = (struct _berelement *)pdu;
	sr = NULL;
	while ((sr = lsa_srv_next(ctx, sr)) != NULL) {
		r = sendto(fd, be->ber_buf, (size_t)(be->ber_end - be->ber_buf),
		    0, (struct sockaddr *)&sr->addr, sizeof(sr->addr));
		if (poll(&pingchk, 1, 100) == 0)
			continue;

		if ((ret = ber_alloc()) == NULL)
			goto fail;		
		rbe = (struct _berelement *)ret;
		recvfrom(fd, rbe->ber_buf, (size_t)(rbe->ber_end - rbe->ber_buf), 
		    0, (struct sockaddr *)&addr, &addrlen);

		if ((dci = malloc(sizeof (DOMAIN_CONTROLLER_INFO))) == NULL) {
			ber_free(ret, 1);
			goto fail;
		}
		dci->DomainControllerName = dcname;

		r = lsa_cldap_parse(ret, dci);
		ber_free(ret, 1);
		if (r == 0)
			break;
		if (r > 1)
			goto fail;
	}

	if (sr == NULL)
		goto fail;

	paddr = (struct sockaddr_in6 *)&addr;
	inet_ntop(paddr->sin6_family, &paddr->sin6_addr, dcaddr+2, 
	    INET6_ADDRSTRLEN);
	dci->DomainControllerAddress = dcaddr;
	dci->DomainControllerAddressType = DS_INET_ADDRESS;

	ber_free(pdu, 1);
	lsa_srv_fini(ctx);
	close(fd);
	return (dci);

 fail:
	lsa_srv_fini(ctx);
	if (dci)
		freedci(dci);
	else
		free(dcname);
	free(dcaddr);
	ber_free(pdu, 1);
	if (fd >= 0)
		close(fd);
	return (NULL);
}
