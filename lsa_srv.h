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

#ifndef _LSA_SRV_H
#define _LSA_SRV_H

#include <sys/list.h>
#include <resolv.h>

typedef struct srv_rr
{
	list_node_t	sr_node;
	boolean_t	sr_used;
	char		*sr_name;
	uint16_t	sr_port;
	uint16_t	sr_priority;
	uint16_t	sr_weight;
} srv_rr_t;

typedef struct lsa_srv_ctx
{
	struct __res_state	lsc_state;
	list_t			lsc_list;
} lsa_srv_ctx_t;

lsa_srv_ctx_t *lsa_srv_init(void);

void lsa_srv_fini(lsa_srv_ctx_t *);

int lsa_srv_lookup(lsa_srv_ctx_t *, const char *, const char *);

srv_rr_t *lsa_srv_next(lsa_srv_ctx_t *, srv_rr_t *);

#endif /* _LSA_SRV_H */
