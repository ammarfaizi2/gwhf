// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"
#include "http/request.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void set_end_of_resp(struct gwhf_client *cl)
{
	cl->state = T_CLST_END_OF_RESP;
	cl->req_buf_off = 0;
}

static bool is_eligible_for_keep_alive(struct gwhf_client *cl)
{
	struct gwhf_req_hdr *hdr = &cl->req_hdr;
	char *val;

	if (!cl->res_buf) {
		/*
		 * If the response buffer is NULL, then it means
		 * that the sever has not sent any response.
		 *
		 * Don't allow keep-alive.
		 */
		return false;
	}

	assert(cl->state == T_CLST_ROUTE_BODY);
	val = gwhf_req_hdr_get_field(hdr, "connection");
	if (val) {
		/*
		 * If the client sent a "Connection" header, then
		 * we need to check whether the value is "keep-alive".
		 * If it is, then it is eligible for keep-alive.
		 */
		return !strcasecmp(val, "keep-alive");
	}

	/*
	 * If the client did not send a "Connection" header, then
	 * we need to check whether the HTTP version is 1.1.
	 * If it is, then it is eligible for keep-alive.
	 */
	val = gwhf_req_hdr_get_version(hdr);
	return !strcmp(val, "HTTP/1.1");
}

static int iterate_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_header *hdr;
	uint16_t i;

	for (i = 0; i < it->nr_route_header; i++) {
		int ret;

		hdr = &it->route_header[i];
		ret = hdr->exec_cb(ctx, cl);
		switch (ret) {
		case GWHF_ROUTE_EXECUTED:
			return 0;
		case GWHF_ROUTE_NOT_FOUND:
			/*
			 * TODO(ammarfaizi2): Add default 404 page.
			 */
			return 0;
		case GWHF_ROUTE_CONTINUE:
			break;
		}
	}

	set_end_of_resp(cl);
	return 0;
}

static int iterate_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_body *body;
	uint16_t i;

	for (i = 0; i < it->nr_route_body; i++) {
		int ret;

		body = &it->route_body[i];
		ret = body->exec_cb(ctx, cl);
		switch (ret) {
		case GWHF_ROUTE_EXECUTED:
			return 0;
		case GWHF_ROUTE_NOT_FOUND:
			/*
			 * TODO(ammarfaizi2): Add default 404 page.
			 */
			return 0;
		case GWHF_ROUTE_CONTINUE:
			break;
		}
	}

	set_end_of_resp(cl);
	return 0;
}

static int gwhf_exec_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	return iterate_route_header(ctx, cl);
}

static int gwhf_exec_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	return iterate_route_body(ctx, cl);
}

static int realloc_recv_buffer_if_needed(struct gwhf_client *cl)
{
	size_t new_size;
	char *tmp;

	if (likely(cl->req_buf_off < cl->req_buf_len)) {
		/*
		 * The buffer is still not full. Go on!
		 */
		return 0;
	}

	/*
	 * The buffer is full. We need to increase the buffer size.
	 */
	new_size = (size_t)cl->req_buf_len + 4096;
	if (new_size > 65535) {
		/*
		 * Don't allow the buffer size to exceed 65535 bytes.
		 */
		return -ENOMEM;
	}

	tmp = realloc(cl->req_buf, new_size);
	if (unlikely(!tmp)) {
		/*
		 * Out of memory.
		 */
		return -ENOMEM;
	}

	cl->req_buf = tmp;
	cl->req_buf_len = (uint16_t)new_size;
	return 0;
}

static int process_recv_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	uint16_t cur_recv_len = cl->req_buf_off;
	struct gwhf_req_hdr *hdr = &cl->req_hdr;

	assert(cl->state == T_CLST_RECV_BODY);
	assert(hdr->content_length != GWHF_CONTENT_LENGTH_UNINITIALIZED);

	cl->req_buf_off = 0;

	if (hdr->content_length == GWHF_CONTENT_LENGTH_CHUNKED) {
		/*
		 * Currently we don't support chunked transfer encoding.
		 */
		return -EOPNOTSUPP;
	}

	cl->total_req_body_recv += (int64_t)cur_recv_len;
	if (unlikely(cl->total_req_body_recv > hdr->content_length ||
	             hdr->content_length == GWHF_CONTENT_LENGTH_INVALID)) {
		/*
		 * Either the client sent more data than the content
		 * length, or the content length is invalid.
		 */
		return -EINVAL;
	}

	if (cl->total_req_body_recv == hdr->content_length ||
	    hdr->content_length == GWHF_CONTENT_LENGTH_NOT_PRESENT) {
		/*
		 * The request body is complete. We can now process
		 * the request.
		 */
		cl->state = T_CLST_ROUTE_BODY;
		return gwhf_exec_route_body(ctx, cl);
	}

	/*
	 * We need to read more data.
	 */
	return realloc_recv_buffer_if_needed(cl);
}

static int process_recv_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	uint16_t hdr_len;
	int ret;

	assert(cl->total_req_body_recv == 0);

	cl->state = T_CLST_RECV_HEADER;
	ret = gwhf_req_hdr_parse(cl->req_buf, &cl->req_hdr);
	if (unlikely(ret < 0))
		return ret;

	/*
	 * The request header is complete. We can now process
	 * the request.
	 */
	hdr_len = (uint16_t)ret;

	cl->state = T_CLST_ROUTE_HEADER;
	ret = gwhf_exec_route_header(ctx, cl);
	if (unlikely(ret < 0))
		return ret;

	if (cl->req_buf_off > hdr_len) {
		/*
		 * If the received data is larger than the request
		 * header, then we request body has also been received.
		 */
		memmove(cl->req_buf, cl->req_buf + hdr_len, cl->req_buf_off - hdr_len);
		cl->req_buf_off -= hdr_len;
	} else {
		/*
		 * Otherwise, we need to read more data.
		 */
		cl->req_buf_off = 0;
	}

	/*
	 * We're ready to receive the request body.
	 */
	cl->state = T_CLST_RECV_BODY;
	return process_recv_body(ctx, cl);
}

static int process_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl)
{
	switch (cl->state) {
	case T_CLST_IDLE:
	case T_CLST_RECV_HEADER:
		return process_recv_header(ctx, cl);
	case T_CLST_RECV_BODY:
		return process_recv_body(ctx, cl);
	case T_CLST_ROUTE_HEADER:
	case T_CLST_ROUTE_BODY:
	case T_CLST_SEND_HEADER:
	case T_CLST_SEND_BODY:
	case T_CLST_END_OF_RESP:
	default:
		abort();
	}
}

int gwhf_process_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret = 0;

	/*
	 * Keep consuming the received data until the buffer is empty,
	 * or an error occurs.
	 */
	while (cl->req_buf_off > 0) {
		ret = process_recv_buffer(ctx, cl);
		if (unlikely(ret < 0))
			break;
	}

	if (!ret) {
		if (is_eligible_for_keep_alive(cl)) {
			gwhf_soft_reset_client(cl);
			assert(cl->state == T_CLST_IDLE);
			return 0;
		}

		return 0;
	}

	/*
	 * If the error is EAGAIN, then we need to wait for more data.
	 */
	if (ret == -EAGAIN)
		ret = 0;

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
