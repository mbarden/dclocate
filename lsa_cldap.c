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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <netdb.h>
#include "lsa_cldap.h"

extern int ldap_put_filter(BerElement *ber, char *);

static int
lsa_cldap_escape_le64(char *buf, uint64_t val, int bytes)
{
	char *p = buf;

	while (bytes != 0) {
		p += sprintf(p, "\\%.2" PRIx8, (uint8_t)(val & 0xff));
		val >>= 8;
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
int
lsa_cldap_setup_pdu(BerElement *ber, const char *dname,
    const char *host, uint32_t ntver)
{
	int		ret = 0, len = 0, msgid;
	char		*basedn = "";
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

	if (ber_printf(ber, "{it{seeiib", msgid,
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

	/* 
	 * Success
	 */
	ret = msgid;
fail:
	if (ret < 0)
		ber_free(ber, 1);
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

static int
lsa_decode_name(uchar_t *base, uchar_t *cp, char *str)
{
	uchar_t *tmp = NULL, *st = cp;
	uint8_t len;

	/* 
	 * there should probably be some boundary checks on str && cp
	 * maybe pass in strlen && msglen ?
	 */
	while (*cp != 0) {
		if (*cp == 0xc0) {
			if (tmp == NULL)
				tmp = cp + 2;
			cp = base + *(cp+1); 
		}
		for (len = *cp++; len > 0; len--)
			*str++ = *cp++;
		*str++ = '.';
	}
	if (cp != st)
		*(str-1) = '\0';
	else
		*str = '\0';
	
	return ((tmp == NULL ? cp+1 : tmp) - st);
}

int
lsa_cldap_parse(BerElement *ber, DOMAIN_CONTROLLER_INFO *dci)
{ 
	uchar_t *base = NULL, *cp = NULL;
	char val[512]; /* how big should val be? */
	int l, i, msgid, rc = 0;
	uint16_t opcode;
	uint8_t *gid = dci->DomainGuid;
	field_5ex_t f = OPCODE;
	
	/* 
	 * Later, compare msgid's/some validation?
	 */

	if (ber_scanf(ber, "{i{x{{x[la", &msgid, &l, &cp) == LBER_ERROR) {
		rc = 1;
		goto out;
	}

	for (base = cp; ((cp - base) < l) && (f <= LM_20_TOKEN); f++) {	  
		val[0] = '\0';
	  	switch(f) {
		case OPCODE:
			opcode = *(uint16_t *)cp;
			cp +=2;
		  /* If there really is an alignment issue, when can do this
			opcode = *cp++;
			opcode |= (*cp++ << 8);
			*/
			break;
		case SBZ:
			cp +=2;
			break;
		case FLAGS:
			dci->Flags = *(uint32_t *)cp;
			cp +=4;
		  /* If there really is an alignment issue, when can do this
			dci->Flags = *cp++;
			for(i = 1; i < 4; i++)
				dci->Flags |= (*cp++ << 8*i);
		  */
			break;
		case DOMAIN_GUID:
			for (i = 0; i < 16; i++)
				gid[i] = *cp++;
			break;
		case FOREST_NAME:
			cp += lsa_decode_name(base, cp, val);
			if ((dci->DnsForestName = strdup(val)) == NULL) {
				rc = 2;
				goto out;
			}
			break;
		case DNS_DOMAIN_NAME:
			cp += lsa_decode_name(base, cp, val);
			if ((dci->DomainName = strdup(val)) == NULL) {
				rc = 2;
				goto out;
			}
			break;
		case DNS_HOST_NAME:
			cp += lsa_decode_name(base, cp, val);
			if (((strncpy(dci->DomainControllerName, "\\\\", 
			    3)) == NULL) || (strcat(dci->DomainControllerName, 
				val) == NULL)) {
				rc = 2;
				goto out;
			}
			break;
		case NET_DOMAIN_NAME:
			/* 
			 * DCI doesn't seem to use this
			 */
			cp += lsa_decode_name(base, cp, val); 
			break;
		case NET_COMP_NAME:
			/* 
			 * DCI doesn't seem to use this
			 */
			cp += lsa_decode_name(base, cp, val); 
			break;
		case USER_NAME:
			/* 
			 * DCI doesn't seem to use this
			 */
			cp += lsa_decode_name(base, cp, val);
			break;
		case DC_SITE_NAME:
			cp += lsa_decode_name(base, cp, val);
			if ((dci->DcSiteName = strdup(val)) == NULL) {
				rc = 2;
				goto out;
			}
			break;
		case CLIENT_SITE_NAME:
			cp += lsa_decode_name(base, cp, val);
			if (((dci->ClientSiteName = strdup(val)) == NULL) && 
			    (val[0] != '\0')) {
				rc = 2;
				goto out;
			}
			break;
		/*
		 * These are all possible, but we don't really care about them.
		 * Sockaddr_size && sockaddr might be useful at some point
		 */
		case SOCKADDR_SIZE:
		case SOCKADDR:
		case NEXT_CLOSEST_SITE_NAME:
		case NTVER:
		case LM_NT_TOKEN:
		case LM_20_TOKEN:
			break;
		default:
			rc = 3;
			goto out;
		}
	}
	
 out:
	if (base)
		free(base);
	else if (cp)
		free(cp);
	return (rc);
}

void
freedci(DOMAIN_CONTROLLER_INFO *dci)
{
	if (dci == NULL)
		return;
	free(dci->DomainControllerName);
	free(dci->DomainControllerAddress);
	free(dci->DomainName);
	free(dci->DnsForestName);
	free(dci->DcSiteName);
	free(dci->ClientSiteName);
	free(dci);
}
