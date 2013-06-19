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
#include <inttypes.h>
#include "lsa_srv.h"

int main(int argc, char **argv)
{
	lsa_srv_ctx_t	*ctx;
	int		r;
	srv_rr_t	*sr = NULL;

	if (argc != 3) {
		fprintf(stderr, "usage: %s rr domain\n", argv[0]);
		return (1);
	}

	ctx = lsa_srv_init();
	if (ctx == NULL) {
		return (1);
	}


	printf("attempting lookup for %s in domain %s\n", argv[1], argv[2]);
	r = lsa_srv_lookup(ctx, argv[1], argv[2]);
	if (r < 0) {
		fprintf(stderr, "error in lookup\n");
		return (1);
	}

	while ((sr = lsa_srv_next(ctx, sr)) != NULL)
	{
		printf("target %s:%" PRIu16
		    ", pri %" PRIu16 ", weight %" PRIu16 "\n",
		    sr->sr_name, sr->sr_port, sr->sr_priority, sr->sr_weight);
	}

	lsa_srv_fini(ctx);
	return (0);
}
