// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"
#include "http/request.h"
#include "http/response.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int process_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl);

static int process_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	uint16_t hdr_len;
	int ret;

	if (unlikely(cl->req_buf_len < 5))
		return -EAGAIN;

	ret = gwhf_req_hdr_parse(cl->req_buf, &cl->req_hdr);
	if (unlikely(ret < 0))
		return ret;

	hdr_len = (uint16_t)ret;
	assert(hdr_len <= cl->req_buf_len);

	/*
	 * The request body might have been received together with the
	 * header. If so, memmove() the request body to the beginning of
	 * the buffer and update the length.
	 */
	if (hdr_len < cl->req_buf_len) {
		char *buf = cl->req_buf;
		char *src = &buf[hdr_len];
		size_t len = cl->req_buf_len - hdr_len;

		memmove(buf, src, len);
		cl->req_buf_len -= hdr_len;
	} else {
		cl->req_buf_len = 0;
	}

	cl->state = T_CLST_ROUTE_HEADER;
	return process_recv_buffer(ctx, cl);
}

static int construct_404_route(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_res_hdr *hdr = &cl->res_hdr;
	int ret;

	ret = gwhf_res_body_add_buf(cl, "404 Not Found", 13);
	if (ret)
		return -ENOMEM;

	gwhf_res_hdr_set_status_code(hdr, 200);
	ret |= gwhf_res_hdr_set_content_type(hdr, "text/plain; charset=utf-8");
	ret |= gwhf_res_hdr_set_content_length(hdr, 5);
	if (ret)
		return -ENOMEM;

	return 0;
}

static int decide_route_result(struct gwhf *ctx, struct gwhf_client *cl, int res)
{
	int ret = 0;

	switch (res) {
	case GWHF_ROUTE_NOT_FOUND:
		ret = construct_404_route(ctx, cl);
		break;
	case GWHF_ROUTE_ERROR:
		ret = -ECONNABORTED;
		break;
	case GWHF_ROUTE_CONTINUE:
		ret = 0;
		break;
	}

	return ret;
}

static int process_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_header *hdr;
	uint16_t i;
	int ret;

	for (i = 0; i < it->nr_route_header; i++) {
		hdr = &it->route_header[i];
		ret = hdr->exec_cb(ctx, cl);
		if (ret == GWHF_ROUTE_ERROR)
			return -ECONNABORTED;
	}

	cl->state = T_CLST_RECV_BODY;
	return process_recv_buffer(ctx, cl);
}

static int process_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_req_hdr *hdr = &cl->req_hdr;
	int64_t con_len;

	cl->total_req_body_recv += (int64_t)cl->req_buf_len;
	con_len = hdr->content_length;
	assert(con_len != GWHF_CONTENT_LENGTH_UNINITIALIZED);

	if (con_len == GWHF_CONTENT_LENGTH_CHUNKED ||
	    con_len == GWHF_CONTENT_LENGTH_INVALID) {
		/*
		 * TODO: Implement chunked transfer encoding.
		 *
		 * Currently, the server does not support chunked transfer
		 * encoding. Drop the connection.
		 */
		return -ECONNABORTED;
	} else if (con_len == 0) {
		/*
		 * The request body is empty. Process the request.
		 */
		cl->state = T_CLST_ROUTE_BODY;
	} else if (con_len == GWHF_CONTENT_LENGTH_NOT_PRESENT) {
		/*
		 * TODO(ammarfaizi2): Handle POST request without
		 *                    a Content-Length header.
		 */
		cl->state = T_CLST_ROUTE_BODY;
	} else if (cl->total_req_body_recv > con_len) {
		/*
		 * The request body is too large. Drop the connection.
		 */
		return -EINVAL;
	} else if (cl->total_req_body_recv == con_len) {
		/*
		 * The request body is complete. Process the request.
		 */
		cl->state = T_CLST_ROUTE_BODY;
	} else {
		/*
		 * The request body is not complete yet.
		 */
		return -EAGAIN;
	}

	return process_recv_buffer(ctx, cl);
}

static int process_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_body *body;
	uint16_t i;
	int ret;

	for (i = 0; i < it->nr_route_body; i++) {
		body = &it->route_body[i];
		ret = body->exec_cb(ctx, cl);
		ret = decide_route_result(ctx, cl, ret);
		if (ret)
			return ret;
	}

	cl->state = T_CLST_IDLE;
	return 0;
}

static int process_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret = 0;

	switch (cl->state) {
	case T_CLST_IDLE:
	case T_CLST_RECV_HEADER:
		ret = process_header(ctx, cl);
		break;
	case T_CLST_ROUTE_HEADER:
		ret = process_route_header(ctx, cl);
		break;
	case T_CLST_RECV_BODY:
		ret = process_body(ctx, cl);
		break;
	case T_CLST_ROUTE_BODY:
		ret = process_route_body(ctx, cl);
		break;
	}

	return ret;
}

int gwhf_consume_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = process_recv_buffer(ctx, cl);
	if (ret >= 0)
		return 0;

	return ret;
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
			  int (*callback)(struct gwhf *, struct gwhf_client *))
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
	return 0;
}

int gwhf_add_route_body(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *))
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
	return 0;
}
