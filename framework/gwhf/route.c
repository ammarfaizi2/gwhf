// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd.
 */

#include "./internal.h"

__cold
int gwhf_route_add_on_body(struct gwhf *ctx, gwhf_route_cb cb,
			   gwhf_route_init_cb init_cb,
			   gwhf_route_free_cb free_cb,
			   void *arg)
{
	struct gwhf_internal *ctxi = ctx->internal;
	uint16_t new_nr = ctxi->nr_rt_on_body + 1;
	struct gwhf_route *rob;

	rob = realloc(ctxi->routes_on_body, sizeof(*rob) * new_nr);
	if (!rob)
		return -ENOMEM;

	rob[new_nr - 1].cb = cb;
	rob[new_nr - 1].init_cb = init_cb;
	rob[new_nr - 1].free_cb = free_cb;
	rob[new_nr - 1].arg = arg;
	ctxi->nr_rt_on_body = new_nr;
	return 0;
}

__cold
int gwhf_route_add_on_header(struct gwhf *ctx, gwhf_route_cb cb,
			     gwhf_route_init_cb init_cb,
			     gwhf_route_free_cb free_cb,
			     void *arg)
{
	struct gwhf_internal *ctxi = ctx->internal;
	uint16_t new_nr = ctxi->nr_rt_on_header + 1;
	struct gwhf_route *roh;

	roh = realloc(ctxi->routes_on_header, sizeof(*roh) * new_nr);
	if (!roh)
		return -ENOMEM;

	roh[new_nr - 1].cb = cb;
	roh[new_nr - 1].init_cb = init_cb;
	roh[new_nr - 1].free_cb = free_cb;
	roh[new_nr - 1].arg = arg;
	ctxi->nr_rt_on_header = new_nr;
	return 0;
}
