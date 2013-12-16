/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * DNS SRV record lookup for AD Domain Controllers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <ldap.h>
#include "lsa_srv.h"

static void
lsa_srvlist_insert(list_t *l, srv_rr_t *rr)
{
        srv_rr_t *sr;
        uint16_t pri = rr->sr_priority;
        uint16_t weight = rr->sr_weight;

        for (sr = list_tail(l); sr != NULL; sr = list_prev(l, sr)) {
                if ((sr->sr_priority < pri) ||
                    ((sr->sr_priority == pri) && (sr->sr_weight < weight))) {
                        list_insert_after(l, sr, rr);
                        return;
                }
        }

        list_insert_head(l, rr);
}

static void
lsa_addrlist_destroy(list_t *l)
{
	addr_rr_t *ar;
	
	for (ar = list_head(l); ar != NULL; ar = list_head(l)) {
		free(ar->name);
		free(ar->addr);
		list_remove_head(l);
		free(ar);
	}
}

static void
lsa_srvlist_destroy(list_t *l)
{
	srv_rr_t *sr;

	for (sr = list_head(l); sr != NULL; sr = list_head(l)) {
		free(sr->sr_name);
		list_remove_head(l);
		free(sr);
	}
}

/*
 * Parse SRV record into a srv_rr_t.
 * Returns a pointer to the next record on success, NULL on failure.
 */

static int
lsa_parse_srv(const uchar_t *msg, const uchar_t *eom, uchar_t **cp,
    uchar_t *namebuf, size_t bufsize, srv_rr_t *sr)
{
	/*
	 * Get priority, weight, port, and target name.
	 */
	uint16_t priority, weight, port;
	int len;
	char *name;

	NS_GET16(priority, *cp);
	NS_GET16(weight, *cp);
	NS_GET16(port, *cp);
	len = dn_expand(msg, eom, *cp, namebuf, bufsize);
	if (len < 0)
		return P_ERR_FAIL;

	/*
	 * According to RFC 2782, SRV records for which there is no service
	 * use target ".".
	 */
	if (namebuf[0] == '.' && namebuf[1] == '\0')
		return P_ERR_SKIP;
		
	if ((name = strdup(namebuf)) == NULL)
		return P_ERR_FAIL;

	sr->sr_name = name;
	sr->sr_port = port;
	sr->sr_priority = priority;
	sr->sr_weight = weight;

	return P_SUCCESS;
}

/* 
 * Parse A record into a v4-mapped IPv6 address.
 */

static int
lsa_parse_a(const uchar_t *msg, const uchar_t *eom, uchar_t **cp,
    uchar_t *namebuf, addr_rr_t *ar)
{

	in6_addr_t *addr6 = NULL;
	char *name = NULL;
	int i;

	if ((name = strdup(namebuf)) == NULL)
		goto fail;	

	if ((addr6 = malloc(sizeof (*addr6))) == NULL) 
		goto fail;

	addr6->s6_addr32[1] = addr6->s6_addr32[0] = 0;
	addr6->s6_addr32[2] = 0xffff0000;
	/*
	addr6->s6_addr32[3] = *(uint32_t *)*cp;
	*cp += 4;
	*/
	
	for (i = 12; i < 16; i++)
	  addr6->s6_addr8[i] = *(*cp)++;
	
	if (*cp > eom)
		goto fail;

	ar->addr = addr6;
	ar->name = name;
	ar->type = AF_INET;
	return P_SUCCESS;

 fail:
	free(addr6);
	free(name);
	return P_ERR_FAIL;
} 

static int
lsa_parse_aaaa(const uchar_t *msg, const uchar_t *eom, uchar_t **cp,
    uchar_t *namebuf, addr_rr_t *ar)
{
	int i;
	in6_addr_t *addr6 = NULL;
	char *name = NULL;

	if ((name = strdup(namebuf)) == NULL)
		goto fail;
	
	if ((addr6 = malloc(sizeof (*addr6))) == NULL)
		goto fail;

	/*	
	for (i = 0; i < 4; i++) {
		addr6->s6_addr32[i] = *(uint32_t *)*cp;
		*cp += 4;
	}
	*/
	
	for (i = 0; i < 16; i++)
	  addr6->s6_addr8[i] = *(*cp)++;
	
	if (*cp > eom)
		goto fail;
	
	ar->addr = addr6;
	ar->name = name;
	ar->type = AF_INET6;
	return P_SUCCESS;

 fail:
	free(addr6);
	free(name);
	return P_ERR_FAIL;
} 

static int
lsa_parse_common(const uchar_t *msg, const uchar_t *eom, uchar_t **cp,
    void *rr)
{
	uchar_t		namebuf[NS_MAXDNAME];
	uint16_t	type, class, size;
	uint32_t	ttl;
	int		len;

	/*
	 * Skip searched RR name and attributes.
	 */
	len = dn_expand(msg, eom, *cp, namebuf, sizeof (namebuf));
	if (len < 0)
		return P_ERR_FAIL;
	
	*cp += len;

	/* 
	 * We started on a compressed name, so we need to adjust cp
	 */
	if (**cp == 0xc0) 
		*cp += 2;

	NS_GET16(type, *cp);
	NS_GET16(class, *cp);
	NS_GET32(ttl, *cp);
	NS_GET16(size, *cp);

	if ((*cp + size) > eom)
		return P_ERR_FAIL;

	if (type == T_SRV)
		return lsa_parse_srv(msg, eom, cp, namebuf, sizeof(namebuf), 
		    (srv_rr_t *) rr);
	if (type == T_A)
		return lsa_parse_a(msg, eom, cp, namebuf, (addr_rr_t *) rr);
	if (type == T_AAAA)
		return lsa_parse_aaaa(msg, eom, cp, namebuf, (addr_rr_t *) rr);

	/* 
	 * If we get here, skip parsing the record entirely;
	 * we're not interested.
	 */
	*cp += size;
	return P_ERR_SKIP;
}

/*
 * Look up and return a sorted list of SRV records for a domain.
 * Returns number of records on success, -1 on failure.
 * Also matches associated A records if returned, and gets them if not.
 */
int
lsa_srv_lookup(lsa_srv_ctx_t *ctx, const char *svcname, const char *dname)
{
	int	ret = -1, anslen, len, n, nq, na, ns, nr, e, skip = 0;
	union
	{
		HEADER h;
		uchar_t b[NS_MAXMSG];
	} *ansbuf;
	uchar_t	*ap, *eom;
	char	namebuf[NS_MAXDNAME];
	list_t la;
	srv_rr_t *sr;

	list_create(&la, sizeof (addr_rr_t), offsetof(addr_rr_t, addr_node));

	ansbuf = malloc(sizeof (*ansbuf));
	if (ansbuf == NULL)
		goto out;

	ap = ansbuf->b;

	/*
	 * Use virtual circuits (TCP) for resolver.
	 */
	ctx->lsc_state.options |= RES_USEVC;

	/*
	 * Traverse parent domains until an answer is found.
	 */

	anslen = res_nquerydomain(&ctx->lsc_state, svcname, dname, C_IN, T_SRV,
	    ap, sizeof (*ansbuf));

	if (anslen > sizeof (*ansbuf) || anslen <= (HFIXEDSZ + QFIXEDSZ))
		goto out;

	eom = ap + anslen;

	/*
	 * Get question and answer count.
	 */
	nq = ntohs(ansbuf->h.qdcount);
	na = ntohs(ansbuf->h.ancount);
	ns = ntohs(ansbuf->h.nscount);
	nr = ntohs(ansbuf->h.arcount);
	if (nq != 1 || na < 1)
		goto  out;

	/*
	 * Skip header and question.
	 */
	ap += HFIXEDSZ;

	len = dn_expand(ansbuf->b, eom, ap, namebuf, sizeof (namebuf));
	if (len < 0)
		goto out;

	ap += len + QFIXEDSZ;

	/*
	 * Expand names in answer(s) and insert into RR list.
	 */
	for (n = 0; (n < na) && (ap < eom); n++) {
		sr = malloc(sizeof (srv_rr_t));
		if (sr == NULL) {
			lsa_srvlist_destroy(&ctx->lsc_list);
			goto out;
		}

		memset(sr, 0, sizeof (*sr));

		e = lsa_parse_common(ansbuf->b, eom, &ap, sr);
		if (e == P_ERR_FAIL) {
			free(sr);
			lsa_srvlist_destroy(&ctx->lsc_list);
			goto out;
		}
		if (e == P_ERR_SKIP) {
		  	skip++;
			free(sr);
			continue;
		}
		lsa_srvlist_insert(&ctx->lsc_list, sr);
	}

	/* Return number of records found. */
	ret = n - skip;
	if (ret == 0)
		goto out;

	for (n = 0; (n < (ns + nr)) && (ap < eom); n++) {
	  	addr_rr_t *ar = malloc(sizeof (addr_rr_t));
		if (ar == NULL)
			goto out;

		memset(ar, 0, sizeof (*ar));
		e = lsa_parse_common(ansbuf->b, eom, &ap, ar);
		if (e == P_ERR_FAIL)
			goto out;
		if (e == P_ERR_SKIP) {
			free(ar);
			continue;
		}
		/* 
		 * Do we care about using IPv6 if its available, or
		 * should we only use it if it's the only one available?
		 * This currently sets up the next loop to "fall back" to 
		 * v4-mapped IPv6 if pure IPv6 wasn't provided.
		 */
		
		if (ar->type == AF_INET)
			list_insert_tail(&la, ar);
		else
			list_insert_head(&la, ar);
	}
	
	for (sr = list_head(&ctx->lsc_list); sr != NULL;
	     sr = list_next(&ctx->lsc_list, sr)) {
		addr_rr_t *ar = NULL;
		sr->addr.sin6_family = AF_INET6;
		sr->addr.sin6_port = htons(LDAP_PORT);
		for (ar = list_head(&la); ar != NULL; ar = list_next(&la, ar))
			if (strcmp(sr->sr_name, ar->name) == 0) {
				sr->addr.sin6_addr = *ar->addr;
				break;
			}
		if (ar == NULL) {
			struct addrinfo *res = NULL;
			struct addrinfo ai = {
				AI_ADDRCONFIG | AI_V4MAPPED, AF_INET6,
				0, 0, 0, NULL, NULL, NULL
			};
			struct sockaddr_in6 sa;
			if ((getaddrinfo(sr->sr_name, NULL, &ai, &res) != 0)
			    || (res == NULL)) {
				ret = -1;
				goto out;
			}
			(void) memcpy(&sa, res->ai_addr, res->ai_addrlen);
			sr->addr.sin6_addr = sa.sin6_addr;
			freeaddrinfo(res);
		}	    
	}
		  
out:
	free(ansbuf);
	lsa_addrlist_destroy(&la);
	list_destroy(&la);
	return (ret);
}

lsa_srv_ctx_t *
lsa_srv_init(void)
{
	lsa_srv_ctx_t *ctx;

	ctx = malloc(sizeof (*ctx));
	if (ctx == NULL)
		return (NULL);

	memset(&ctx->lsc_state, 0, sizeof(ctx->lsc_state));
	if (res_ninit(&ctx->lsc_state) != 0) {
		free(ctx);
		return (NULL);
	}

	list_create(&ctx->lsc_list, sizeof (srv_rr_t),
	    offsetof(srv_rr_t, sr_node));

	return (ctx);
}

void
lsa_srv_fini(lsa_srv_ctx_t *ctx)
{
  	if (ctx == NULL)
  		return;
	lsa_srvlist_destroy(&ctx->lsc_list);
	list_destroy(&ctx->lsc_list);
	res_ndestroy(&ctx->lsc_state);
	free(ctx);
}

static void
lsa_srv_reset(lsa_srv_ctx_t *ctx)
{
	list_t *l = &ctx->lsc_list;
	srv_rr_t *sr;

	for (sr = list_head(l); sr != NULL; sr = list_next(l, sr)) {
		sr->sr_used = B_FALSE;
	}
}

srv_rr_t *
lsa_srv_next(lsa_srv_ctx_t *ctx, srv_rr_t *rr)
{
	list_t		*l = &ctx->lsc_list;
	srv_rr_t	*sr, *first = NULL;
	uint16_t	pri = 0;
	uint32_t	sum = 0, r;

	if (rr == NULL) {
		/*
		 * Start over and mark all records unused.
		 */
		lsa_srv_reset(ctx);
	} else {
		rr->sr_used = B_TRUE;
		pri = rr->sr_priority;
	}

	for (sr = list_head(l); sr != NULL; sr = list_next(l, sr)) {
		/*
		 * Skip used and lower-numbered priority records.
		 */
		if ((sr->sr_used) || (sr->sr_priority < pri))
			continue;

		if (sr->sr_priority > pri) {
			/* 
			 * Have we seen all of the records with the
			 * current priority?
			 */
			if (first != NULL)
				break;
			/* Try the next priority number */
			first = sr;
			pri = sr->sr_priority;
		} else {
			/*
			 * Remember the first unused record at this priority.
			 */
			if (first == NULL)
				first = sr;
		}
		
		/*
		 * Sum the weights at this priority, for randomised selection.
		 */
		/*sum += sr->sr_weight;*/
	}

	/*
	 * No more records remaining?
	 */
	if (first == NULL)
		return (NULL);
	/*
	 * If all weights are 0, return first unused record.
	 */

	/* XXX this will always trigger until weight is implemented */
	if (sum == 0)
		return (first);

	/*
	 * Generate a random number in the interval [0, sum].
	 */
	r = random() % (sum + 1);

	/*
	 * Go through all of the records at the current priority to locate
	 * the next selection.
	 */
	sum = 0;
	for (sr = first; sr != NULL; sr = list_next(l, sr)) {
		if (sr->sr_used)
			continue;
		/*
		 * We somehow fell off the end?
		 */
		if (sr->sr_priority > pri) {
			sr = NULL;
			break;
		}

		/*
		 * Since the ordering is constant, we know the next record
		 * will be found when the random number from the range
		 * falls between the previous sum and the current sum.
		 */
		sum += sr->sr_weight;
		if (sum >= r)
			break;
	}

	return (sr);
}
