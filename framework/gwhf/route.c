// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd.
 */

#include "./internal.h"

#include <stdio.h>

static int route_init_on_body(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *rob = ctxi->routes_on_body;
	uint16_t i;

	if (!rob)
		return 0;

	for (i = 0; i < ctxi->nr_rt_on_body; i++) {
		if (rob[i].init_cb) {
			int ret = rob[i].init_cb(ctx, rob[i].arg);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int route_init_on_header(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *roh = ctxi->routes_on_header;
	uint16_t i;

	if (!roh)
		return 0;

	for (i = 0; i < ctxi->nr_rt_on_header; i++) {
		if (roh[i].init_cb) {
			int ret = roh[i].init_cb(ctx, roh[i].arg);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void route_destroy_on_body(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *rob = ctxi->routes_on_body;
	uint16_t i;

	if (!rob)
		return;

	for (i = 0; i < ctxi->nr_rt_on_body; i++) {
		if (rob[i].free_cb)
			rob[i].free_cb(ctx, rob[i].arg);
	}

	free(rob);
	ctxi->routes_on_body = NULL;
	ctxi->nr_rt_on_body = 0;
}

static void route_destroy_on_header(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *roh = ctxi->routes_on_header;
	uint16_t i;

	if (!roh)
		return;

	for (i = 0; i < ctxi->nr_rt_on_header; i++) {
		if (roh[i].free_cb)
			roh[i].free_cb(ctx, roh[i].arg);
	}

	free(roh);
	ctxi->routes_on_header = NULL;
	ctxi->nr_rt_on_header = 0;
}

__cold
int gwhf_route_init(struct gwhf *ctx)
{
	int ret;

	ret = route_init_on_body(ctx);
	if (ret)
		return ret;

	ret = route_init_on_header(ctx);
	if (ret)
		return ret;

	return 0;
}

__cold
void gwhf_route_destroy(struct gwhf *ctx)
{
	route_destroy_on_body(ctx);
	route_destroy_on_header(ctx);
}

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
	ctxi->routes_on_body = rob;
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
	ctxi->routes_on_header = roh;
	ctxi->nr_rt_on_header = new_nr;
	return 0;
}

static int handle_route_executed(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_http_res *res = &str->res;
	size_t len;
	char *buf;
	int ret;

	ret = gwhf_http_res_construct_first_res(res, &buf, &len);
	if (ret)
		return ret;

	str->state = TCL_SEND_HEADER;
	cl->send_buf.buf = buf;
	cl->send_buf.len = len;
	cl->send_buf.alloc = len;
	return 0;
}

static int handle_route(struct gwhf *ctx, struct gwhf_client *cl, int ret)
{
	switch (ret) {
	case GWHF_ROUTE_EXECUTED:
		return handle_route_executed(ctx, cl);
	}

	return ret;
}

__hot
int gwhf_route_exec_on_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *roh = ctxi->routes_on_header;
	uint16_t i;

	if (!roh)
		return 0;

	for (i = 0; i < ctxi->nr_rt_on_header; i++) {
		int ret = roh[i].cb(ctx, cl, roh[i].arg);
		if (ret != GWHF_ROUTE_CONTINUE)
			return handle_route(ctx, cl, ret);
	}

	return GWHF_ROUTE_CONTINUE;
}

__hot
int gwhf_route_exec_on_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_route *rob = ctxi->routes_on_body;
	uint16_t i;

	if (!rob)
		return 0;

	for (i = 0; i < ctxi->nr_rt_on_body; i++) {
		int ret = rob[i].cb(ctx, cl, rob[i].arg);
		if (ret != GWHF_ROUTE_CONTINUE)
			return handle_route(ctx, cl, ret);
	}

	return GWHF_ROUTE_CONTINUE;
}
