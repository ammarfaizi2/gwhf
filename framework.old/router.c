// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#include "internal.h"
#include "ev/epoll.h"
#include "http/request.h"
#include "http/response.h"

#include <string.h>
#include <stdio.h>

static int route_not_found(struct gwhf_client *cl)
{
	static const char str[] = "404 Not Found\n";
	size_t len = sizeof(str) - 1;
	int ret = 0;

	gwhf_set_http_res_code(cl, 404);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Type", "text/plain");
	ret |= gwhf_add_http_res_hdr(cl, "Content-Length", "%zu", len);
	ret |= gwhf_set_http_res_body_buf_ref(cl, str, len);
	return ret;
}

static int route_internal_server_error(struct gwhf *ctx, struct gwhf_client *cl)
{
	static const char str[] = "500 Internal Server Error\n";
	size_t len = sizeof(str) - 1;
	int ret = 0;

	gwhf_set_http_res_code(cl, 500);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Type", "text/plain");
	ret |= gwhf_add_http_res_hdr(cl, "Content-Length", "%zu", len);
	ret |= gwhf_set_http_res_body_buf_ref(cl, str, len);
	return ret;
}

int gwhf_exec_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];

	(void)ctx;
	(void)cl;

	return 0;
}

static int iterate_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_body *body = it->route_body;
	int ret = GWHF_ROUTE_CONTINUE;
	uint16_t i;

	for (i = 0; i < it->nr_route_body; i++) {
		ret = body[i].exec_cb(ctx, cl, body[i].data);
		if (ret < 0)
			return ret;

		switch (ret) {
		case GWHF_ROUTE_EXECUTE:
		case GWHF_ROUTE_NOT_FOUND:
		case GWHF_ROUTE_ERROR:
			goto out;
		case GWHF_ROUTE_CONTINUE:
			break;
		}
	}

out:
	return ret;
}

int gwhf_exec_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = iterate_route_body(ctx, cl);
	if (unlikely(ret < 0))
		return ret;

	switch (ret) {
	case GWHF_ROUTE_EXECUTE:
		break;
	case GWHF_ROUTE_CONTINUE:
	case GWHF_ROUTE_NOT_FOUND:
		ret = route_not_found(cl);
		break;
	case GWHF_ROUTE_ERROR:
		ret = route_internal_server_error(ctx, cl);
		break;
	}

	if (unlikely(ret < 0))
		return ret;

	cl->streams[0].state = T_CL_STREAM_SEND_HEADER;
	return 0;
}

void gwhf_destroy_route_header(struct gwhf_internal *it)
{
	free(it->route_header);
	it->route_header = NULL;
	it->nr_route_header = 0;
}

void gwhf_destroy_route_body(struct gwhf_internal *it)
{
	free(it->route_body);
	it->route_body = NULL;
	it->nr_route_body = 0;
}

int gwhf_add_route_header(struct gwhf *ctx,
			  int (*callback)(struct gwhf *, struct gwhf_client *,
					  void *), void *data)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_header *hdr;
	size_t new_nr;

	if (!it)
		return -EFAULT;

	new_nr = (size_t)it->nr_route_header + 1;
	if (new_nr > 65535)
		return -ENOMEM;

	hdr = realloc(it->route_header, sizeof(*hdr) * new_nr);
	if (!hdr)
		return -ENOMEM;

	it->route_header = hdr;
	it->nr_route_header = (uint16_t)new_nr;
	it->route_header[new_nr - 1].exec_cb = callback;
	it->route_header[new_nr - 1].data = data;
	return 0;
}

int gwhf_add_route_body(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *,
					void *), void *data)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_body *body;
	size_t new_nr;

	if (!it)
		return -EFAULT;

	new_nr = (size_t)it->nr_route_body + 1;
	if (new_nr > 65535)
		return -ENOMEM;

	body = realloc(it->route_body, sizeof(*body) * new_nr);
	if (!body)
		return -ENOMEM;

	it->route_body = body;
	it->nr_route_body = (uint16_t)new_nr;
	it->route_body[new_nr - 1].exec_cb = callback;
	it->route_body[new_nr - 1].data = data;
	return 0;
}
