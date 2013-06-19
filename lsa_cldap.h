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

#ifndef _LSA_CLDAP_H
#define _LSA_CLDAP_H

#include <ldap.h>
#include <sys/list.h>

typedef struct _DOMAIN_CONTROLLER_INFO {
	const char	*DomainControllerName;
	struct sockaddr	*DomainControllerAddress;
	uint8_t		DomainGuid[16];
	const char	*DomainName;
	const char	*DnsForestName;
	uint32_t	Flags;
	const char	*DcSiteName;
	const char	*ClientSiteName;
} DOMAIN_CONTROLLER_INFO;


typedef struct lsa_cldap
{
	int	lc_sock;
	list_t	lc_hostlist;
} lsa_cldap_t;

typedef struct lsa_cldap_host
{
	list_node_t		lch_node;
	hrtime_t		lch_lastping;
	uint16_t		lch_lastmsg;
	DOMAIN_CONTROLLER_INFO	lch_dcinfo;
} lsa_cldap_host_t;

#define NETLOGON_ATTR_NAME			"NetLogon"
#define NETLOGON_NT_VERSION_1			0x00000001
#define NETLOGON_NT_VERSION_5			0x00000002
#define NETLOGON_NT_VERSION_5EX			0x00000004
#define NETLOGON_NT_VERSION_5EX_WITH_IP		0x00000008
#define NETLOGON_NT_VERSION_WITH_CLOSEST_SITE	0x00000010
#define NETLOGON_NT_VERSION_AVOID_NT4EMUL	0x01000000

lsa_cldap_t *lsa_cldap_init(void);

void lsa_cldap_fini(lsa_cldap_t *);

lsa_cldap_host_t *lsa_cldap_open(lsa_cldap_t *, const char *, int16_t);
void lsa_cldap_close(lsa_cldap_host_t *);

int lsa_cldap_netlogon_search(lsa_cldap_t *, lsa_cldap_host_t *,
    const char *, uint32_t);

#endif /* _LSA_CLDAP_H */

