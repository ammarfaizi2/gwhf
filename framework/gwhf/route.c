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
	struct gwhf_buf *rsb = &cl->raw_send_buf;
	struct gwhf_http_res *res = &str->res;
	size_t len;
	char *buf;
	int ret;

	if (gwhf_client_need_keep_alive_hdr(cl))
		ret = gwhf_http_res_add_hdr(res, "Connection", "keep-alive");
	else
		ret = gwhf_http_res_add_hdr(res, "Connection", "close");

	if (ret)
		return ret;

	ret = gwhf_http_res_construct_first_res(res, &buf, &len);
	if (ret)
		return ret;

#ifdef CONFIG_HTTPS
	if (cl->https_state == GWHF_CL_HTTPS_ON) {
		size_t target_len;
		ret = SSL_write(cl->ssl, buf, len);
		free(buf);
		if (ret <= 0)
			return -EIO;

		target_len = rsb->len + len + (ret * 2);

		do {
			ret = gwhf_buf_realloc_if_needed(rsb, target_len);
			if (ret)
				return ret;

			errno = 0;
			ret = BIO_read(cl->wbio, rsb->buf + rsb->len,
				       rsb->alloc - rsb->len);
			if (ret <= 0)
				return -EIO;

			rsb->len += ret;
			target_len += 1024;
		} while (SSL_pending(cl->ssl) == 1);
	} else {
		ret = gwhf_buf_append(rsb, buf, len);
		free(buf);
		if (ret)
			return ret;
	}
#else /* #ifdef CONFIG_HTTPS */
	ret = gwhf_buf_append(rsbf, buf, len);
	free(buf);
	if (ret)
		return ret;
#endif

	str->state = TCL_SEND_HEADER;
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

static int route_404_not_found(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_http_res *res = &str->res;
	int ret;

	ret = gwhf_http_res_set_status_code(res, 404);
	if (ret)
		return ret;

	ret = gwhf_http_res_set_body_buf_ref(res, "404 Not Found\n", 14);
	if (ret)
		return ret;

	ret = gwhf_http_res_add_hdr(res, "Content-Type", "text/plain");
	if (ret)
		return ret;

	ret = gwhf_http_res_add_hdr(res, "Content-Length", "%d", 14);
	if (ret)
		return ret;

	return handle_route_executed(ctx, cl);
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

	return route_404_not_found(ctx, cl);
}
