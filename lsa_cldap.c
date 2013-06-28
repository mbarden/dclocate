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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <lber.h>
#include <ldap.h>

#include "lsa_cldap.h"

extern int ldap_put_filter(BerElement *ber, char *);

struct _berelement {
	char	*ber_buf;
	char	*ber_ptr;
	char	*ber_end;
};

lsa_cldap_t *
lsa_cldap_init()
{
	int			fd;
	lsa_cldap_t		*lc;
	struct sockaddr_in6 	addr;

	if ((fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
		return (NULL);
	/*
	 * Bind to all available addresses and any port.
	 */
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = 0;

	if (bind(fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
		goto fail;

	if ((lc = malloc(sizeof (*lc))) == NULL)
		goto fail;

	lc->lc_sock = fd;
	list_create(&lc->lc_hostlist, sizeof (lsa_cldap_host_t),
	    offsetof(lsa_cldap_host_t, lch_node));
	return (lc);
fail:
	(void) close(fd);

	return (NULL);
}

void
lsa_cldap_fini(lsa_cldap_t *lc)
{
	while (!list_is_empty(&lc->lc_hostlist))
		list_remove_head(&lc->lc_hostlist);
	list_destroy(&lc->lc_hostlist);

	(void) close(lc->lc_sock);
	free(lc);
}

lsa_cldap_host_t *
lsa_cldap_open(lsa_cldap_t *lc, const char *host, int16_t port)
{
	lsa_cldap_host_t	*lch;
	char			*p, *dcaddr, *dcname;
	struct sockaddr_in6 	sa;

	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_loopback;
	sa.sin6_port = htons((port == 0) ? port : LDAP_PORT);

	/*
	 * Attempt to resolve host if specified. Fall back to loopback.
	 */
	if (host != NULL) {
		struct addrinfo	*res;
		struct addrinfo	ai = {
			AI_ADDRCONFIG | AI_V4MAPPED, AF_INET6,
			0, 0, 0, NULL, NULL, NULL
		};

		if ((getaddrinfo(host, NULL, &ai, &res) != 0) ||
		    (res == NULL))
			goto fail;

		(void) memcpy(&sa, res->ai_addr, res->ai_addrlen);

		freeaddrinfo(res);
	}

	if ((lch = malloc(sizeof (*lch))) == NULL)
		goto fail;

	memset(lch, 0, sizeof (*lch));

	if ((dcname = malloc(MAXHOSTNAMELEN + 3)) == NULL)
		goto fail;

	if ((dcaddr = malloc(INET6_ADDRSTRLEN + 2)) == NULL)
		goto fail;

	/*
	 * Look up DC name; DomainControllerName is prefixed with "\\".
	 */
	p = strcpy(dcname, "\\\\") + 2;

	if (getnameinfo((struct sockaddr *)&sa, sizeof (sa),
	    p, MAXHOSTNAMELEN + 1, NULL, 0, NI_NAMEREQD) != 0) {
		/*
		 * Unable to perform reverse lookup on the name, fall back
		 * to specified hostname if one exists, or our hostname.
		 */
		if (host == NULL) {
			if (gethostname(p, MAXHOSTNAMELEN + 1) != 0)
				goto fail;
		} else {
			(void) strlcpy(p, host, MAXHOSTNAMELEN + 1);
		}
	}

	/*
	 * Format DC address; DomainControllerAddress is prefixed with "\\".
	 */
	p = strcpy(dcaddr, "\\\\") + 2;

	if (inet_ntop(AF_INET6, &sa.sin6_addr, p, INET6_ADDRSTRLEN) != 0)
		goto fail;

	lch->lch_dcinfo.DomainControllerName = dcname;
	lch->lch_dcinfo.DomainControllerAddress = dcaddr;
	lch->lch_dcinfo.DomainControllerAddressType = DS_INET_ADDRESS;
	lch->lch_dcinfo.Flags = DS_DNS_CONTROLLER_FLAG;

	return (lch);
fail:
	free(dcaddr);
	free(dcname);
	free(lch);

	return (NULL);
}

void
lsa_cldap_close(lsa_cldap_host_t *lch)
{
	free(lch->lch_dcinfo.DomainControllerAddress);
	free(lch);
}

static int
lsa_cldap_escape_le64(char *buf, uint64_t val, int bytes)
{
	char *p = buf;

	while (bytes != 0) {
		p += sprintf(p, "\\%.2" PRIx8, (uint8_t)(val & 0xff));
		val >>= 1;
		bytes--;
	}

	return (p - buf);
}

/*
 * Construct CLDAPMessage PDU for NetLogon search request.
 *
 *  CLDAPMessage ::= SEQUENCE {
 *      messageID       MessageID,
 *      protocolOp      searchRequest   SearchRequest;
 *  }
 * 
 *  SearchRequest ::=
 *      [APPLICATION 3] SEQUENCE {
 *          baseObject    LDAPDN,
 *          scope         ENUMERATED {
 *                             baseObject            (0),
 *                             singleLevel           (1),
 *                             wholeSubtree          (2)
 *                        },
 *          derefAliases  ENUMERATED {
 *                                     neverDerefAliases     (0),
 *                                     derefInSearching      (1),
 *                                     derefFindingBaseObj   (2),
 *                                     derefAlways           (3)
 *                                },
 *          sizeLimit     INTEGER (0 .. MaxInt),
 *          timeLimit     INTEGER (0 .. MaxInt),
 *          attrsOnly     BOOLEAN,
 *          filter        Filter,
 *          attributes    SEQUENCE OF AttributeType
 *  }
 */
static int
lsa_cldap_setup_pdu(BerElement *ber, const char *dname,
    const char *host, uint32_t ntver)
{
	int		ret = 0, len = 0, msgid;
	char		*ldapdn = "", *basedn = "";
	int scope = LDAP_SCOPE_BASE, deref = LDAP_DEREF_NEVER,
	    sizelimit = 0, timelimit = 0, attrsonly = 0;
	char		filter[MAXHOSTNAMELEN]; 
	char		ntver_esc[13];

	/*
	 * XXX Crappy semi-unique msgid.
	 */
	msgid = gethrtime() & 0xffff;
			
	/*
	 * Encode CLDAPMessage and beginning of SearchRequest sequence.
	 */
	if (ber_printf(ber, "{ist{seeiib", msgid, ldapdn,
	    LDAP_REQ_SEARCH, basedn, scope, deref,
		sizelimit, timelimit, attrsonly) < 0)
		goto fail;
	
	/*
	 * Format NtVer as little-endian with LDAPv3 escapes.
	 */
	lsa_cldap_escape_le64(ntver_esc, ntver, sizeof (ntver));

	/*
	 * Construct search filter in LDAP format.
	 */
	len += snprintf(filter, sizeof (filter), "(&(DnsDomain=%s)", dname);
	if (len >= sizeof (filter))
		goto fail;

	if (host != NULL) {
		len += snprintf(filter + len, sizeof (filter) - len,
		    "(Host=%s)", host);
		if (len >= sizeof (filter))
			goto fail;
	}

	len += snprintf(filter + len, sizeof (filter) - len,
	    "(NtVer=%s))", ntver_esc);
	if (len >= sizeof (filter))
		goto fail;

	/*
	 * Encode Filter sequence.
	 */
	if (ldap_put_filter(ber, filter) < 0)
		goto fail;
	/* 
	 * Encode attribute and close Filter and SearchRequest sequences.
	 */
	if (ber_printf(ber, "{s}}}", NETLOGON_ATTR_NAME) < 0)
		goto fail;

	/* Success */
	ret = msgid;
fail:
	if (ldapdn != NULL)
		free(ldapdn);
	if (ret < 0)
		ber_free(ber, 1);
	return (ret);
}

static ssize_t
lsa_cldap_send_pdu(lsa_cldap_t *lc, BerElement *pdu,
    const struct sockaddr *addr)
{
	socklen_t addrlen = sizeof (struct sockaddr_in);
	struct _berelement *be = (struct _berelement *)pdu;

	if (addr->sa_family == AF_INET6)
		addrlen = sizeof (struct sockaddr_in6);

	return (sendto(lc->lc_sock, be->ber_buf,
	   (size_t)(be->ber_end - be->ber_buf), 0, addr, addrlen));
}

static ssize_t
lsa_cldap_recv_pdu(lsa_cldap_t *lc, BerElement *pdu,
    struct sockaddr *addr, socklen_t *addrlenp)
{
	struct _berelement *be = (struct _berelement *)pdu;

	return (recvfrom(lc->lc_sock, be->ber_buf,
	   (size_t)(be->ber_end - be->ber_buf), 0, addr, addrlenp));
}

int
lsa_cldap_netlogon_search(lsa_cldap_t *lc, lsa_cldap_host_t *lch,
     const char *host, uint32_t ntver)
{
	int			ret = -1;
	uint16_t		msgid;
	BerElement		*pdu;
	struct sockaddr_in6 	addr;

	if ((pdu = ber_alloc()) == NULL)
		goto fail;

	msgid = lsa_cldap_setup_pdu(pdu, lch->lch_dcinfo.DomainName,
	    host, ntver);

	/*
	 * Convert DC address. Port is actually fixed as per MS-CLDAP spec.
	 */
	addr.sin6_family = AF_INET6;
	addr.sin6_port = LDAP_PORT;

	if (strlen(lch->lch_dcinfo.DomainControllerAddress) < 2)
		goto fail;

	if (inet_pton(AF_INET6, lch->lch_dcinfo.DomainControllerAddress + 2,
		&addr.sin6_addr) != 1)
		goto fail;

	/*
	 * Send the PDU to the host
	 */
	if (lsa_cldap_send_pdu(lc, pdu, (struct sockaddr *)&addr));
		goto fail;

	lch->lch_lastping = gethrtime();
	lch->lch_lastmsg = msgid;
	/*
	 * Add or move this host to end of pending host list.
	 */
	if (list_link_active(&lch->lch_node))
		list_remove(&lc->lc_hostlist, lch);
	list_insert_tail(&lc->lc_hostlist, lch);

	ret = 0;
fail:
	if (pdu != NULL)
		ber_free(pdu, 1);
	return (ret);
}

/*
 * Parse incoming search responses and attribute to correct hosts.
 *
 *  CLDAPMessage ::= SEQUENCE {
 *     messageID       MessageID,
 *                     searchResponse  SEQUENCE OF
 *                                         SearchResponse;
 *  }
 *
 *  SearchResponse ::=
 *    CHOICE {
 *         entry          [APPLICATION 4] SEQUENCE {
 *                             objectName     LDAPDN,
 *                             attributes     SEQUENCE OF SEQUENCE {
 *                                              AttributeType,
 *                                              SET OF
 *                                                AttributeValue
 *                                            }
 *                        },
 *         resultCode     [APPLICATION 5] LDAPResult
 *    }
 */
lsa_cldap_host_t *
lsa_cldap_netlogon_reply(lsa_cldap_t *lc)
{
	BerElement		*ber;
	lsa_cldap_host_t	*lch = NULL;
	struct sockaddr_storage addr;
	list_t			*l = &lc->lc_hostlist;
	int			len, msgid;
	socklen_t		addrlen;

	if ((ber = ber_alloc_t(0)) == NULL)
		goto fail;

	len = lsa_cldap_recv_pdu(lc, ber, (struct sockaddr *)&addr, &addrlen);
	/*
	 * Decode CLDAPMessage only.
	 */
	if (ber_scanf(ber, "{i{", &msgid) == LBER_ERROR);
		goto fail;

	/*
	 * Find corresponding host.
	 */
	for (lch = list_head(l); lch != NULL; lch = list_next(l, lch)) {
		if ((lch->lch_lastmsg == msgid) &&
			(memcmp(lch->lch_dcinfo.DomainControllerAddress,
				&addr, addrlen) == 0)) {
			list_remove(&lc->lc_hostlist, lch);
			break;
		}
	}

fail:
	if (ber != NULL)
		ber_free(ber, 1);
	return (lch);
}
