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
	char		*DomainControllerName;
	char		*DomainControllerAddress;
	unsigned long	DomainControllerAddressType;
	uint8_t		DomainGuid[16];
	char		*DomainName;
	char		*DnsForestName;
	unsigned long	Flags;
	char		*DcSiteName;
	char		*ClientSiteName;
} DOMAIN_CONTROLLER_INFO;

struct _berelement {
	char	*ber_buf;
	char	*ber_ptr;
	char	*ber_end;
};

#define DS_INET_ADDRESS		0x0001
#define DS_NETBIOS_ADDRESS	0x0002

#define DS_PDC_FLAG		0x00000001	/* DC is PDC of domain */
#define DS_GC_FLAG		0x00000004	/* DC is GC server for forest */
#define DS_LDAP_FLAG		0x00000008	/* LDAP server */
#define DS_DS_FLAG		0x00000010	/* DC is DS server for domain */
#define DS_KDC_FLAG		0x00000020	/* DC is KDC for domain */
#define DS_TIMESERV_FLAG	0x00000040	/* DC has time service */
#define DS_CLOSEST_FLAG		0x00000080	/* DC in same site as client */
#define DS_WRITABLE_FLAG	0x00000100	/* Writable directory service */
#define DS_GOOD_TIMESERV_FLAG	0x00000200	/* Time service is reliable */
#define DS_NDNC_FLAG		0x00000400	/* Name context not a domain */
#define DS_SELECT_SECRET_DOMAIN_6_FLAG	0x00000800	/* Read-only W2k8 DC */
#define DS_FULL_SECRET_DOMAIN_6_FLAG	0x00001000	/* Writable W2k8 DC */
#define DS_PING_FLAGS		0x0000ffff	/* Flags returned on ping */
#define DS_DNS_CONTROLLER_FLAG	0x20000000	/* DC name is DNS format */
#define DS_DNS_DOMAIN_FLAG	0x40000000	/* Domain name is DNS format */
#define DS_DNS_FOREST_FLAG	0x80000000	/* Forest name is DNS format */

#define NETLOGON_ATTR_NAME			"NetLogon"
#define NETLOGON_NT_VERSION_1			0x00000001
#define NETLOGON_NT_VERSION_5			0x00000002
#define NETLOGON_NT_VERSION_5EX			0x00000004
#define NETLOGON_NT_VERSION_5EX_WITH_IP		0x00000008
#define NETLOGON_NT_VERSION_WITH_CLOSEST_SITE	0x00000010
#define NETLOGON_NT_VERSION_AVOID_NT4EMUL	0x01000000

typedef enum {
	OPCODE = 0,
	SBZ,
	FLAGS,
	DOMAIN_GUID,
	FOREST_NAME,
	DNS_DOMAIN_NAME,
	DNS_HOST_NAME,
	NET_DOMAIN_NAME,
	NET_COMP_NAME,
	USER_NAME,
	DC_SITE_NAME,
	CLIENT_SITE_NAME,
	SOCKADDR_SIZE,
	SOCKADDR,
	NEXT_CLOSEST_SITE_NAME,
	NTVER,
	LM_NT_TOKEN,
	LM_20_TOKEN
} field_5ex_t;

int lsa_cldap_setup_pdu(BerElement *ber, const char *dname, 
    const char *host, uint32_t ntver);

int lsa_cldap_parse(BerElement *, DOMAIN_CONTROLLER_INFO *);

#endif /* _LSA_CLDAP_H */
