#include "lsa_cldap.h"
#include "lsa_srv.h"


DOMAIN_CONTROLLER_INFO *
dc_locate(const char *svcname, const char *dname)
{

	lsa_cldap_t *lc;
	lsa_cldap_host_t *lch;
	lsa_srv_ctx_t *ctx;
	srv_rr_t *sr = NULL;
	DOMAIN_CONTROLLER_INFO *dci = NULL;
	int r;
	
	ctx = lsa_srv_init();
	if (ctx == NULL)
		return (1);

	r = lsa_srv_lookup(ctx, svcname, dname);
	if (r < 0) 
		return (1);
	
	lc = lsa_cldap_init();

	while((sr = lsa_srv_next(ctx, sr)) != NULL) {
		lch = lsa_cldap_open(lc, sr->sr_name, LDAP_PORT);
		r = lsa_cldap_net_logon_search(lc, lch, sr->sr_name, ntver);
		if (r != 0) {
			lsa_cldap_close(lch);
			continue;
		}
	
		/* XXX reply/timeout? */
	
		lsa_cldap_close(lch);
		if ((lch = lsa_cldap_netlogon_reply(lc)) != NULL)
			break;
	}

	if (lch != NULL) {
		dci = (DOMAIN_CONTROLLER_INFO *) malloc(sizeof (DOMAIN_CONTROLLER_INFO));
		*dci = lch->
