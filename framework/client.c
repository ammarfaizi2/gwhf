// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"
#include "ev/epoll.h"
#include "http/request.h"
#include "http/response.h"

#include <string.h>
#include <stdio.h>

static void init_client_first(struct gwhf_client *cl)
{
	cl->fd = -1;
}

__cold
int gwhf_init_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_client *cl, *clients;
	uint16_t i;
	int err;

	clients = calloc(arg->nr_clients, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	err = gwhf_init_stack16(&cs->stack, arg->nr_clients);
	if (err) {
		free(clients);
		return err;
	}

	i = arg->nr_clients;
	while (i--) {
		cl = &clients[i];
		init_client_first(cl);
		err = __gwhf_push_stack16(&cs->stack, i);
		assert(err == 0);
		(void)err;
	}

	cs->clients = clients;
	return 0;
}

static void destroy_client_streams(struct gwhf_client *cl);

static void destroy_client(struct gwhf_client *cl)
{
	if (cl->fd >= 0) {
		close(cl->fd);
		cl->fd = -1;
	}

	destroy_client_streams(cl);
}

__cold
void gwhf_destroy_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	struct gwhf_client *cl, *clients;
	uint16_t i;

	clients = cs->clients;
	if (!clients)
		return;

	for (i = 0; i < cs->stack.size; i++) {
		cl = &clients[i];
		destroy_client(cl);
	}

	free(clients);
	gwhf_destroy_stack16(&cs->stack);
}

static int init_client_stream(struct gwhf_client_stream *cls)
{
	int ret;

	ret = gwhf_init_req_buf(cls);
	if (unlikely(ret))
		return ret;

	ret = gwhf_init_res_buf(cls);
	if (unlikely(ret))
		goto out_req_buf;

	ret = gwhf_init_http_req_hdr(&cls->req_hdr);
	if (unlikely(ret))
		goto out_res_buf;

	cls->state = T_CL_STREAM_IDLE;
	return 0;

out_res_buf:
	gwhf_destroy_res_buf(cls);
out_req_buf:
	gwhf_destroy_req_buf(cls);
	return ret;
}

static void destroy_client_stream(struct gwhf_client_stream *cls)
{
	gwhf_destroy_req_buf(cls);
	gwhf_destroy_res_buf(cls);
	cls->state = T_CL_STREAM_OFF;
}

static int init_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint16_t nr_streams, i;
	int err;

	nr_streams = 1u;
	streams = calloc(nr_streams, sizeof(*streams));
	if (unlikely(!streams))
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		err = init_client_stream(&streams[i]);
		if (unlikely(err))
			goto out_err;
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	return 0;

out_err:
	while (i--)
		destroy_client_stream(&streams[i]);
	free(streams);
	return err;
}

static void destroy_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint16_t nr_streams, i;

	streams = cl->streams;
	nr_streams = cl->nr_streams;
	if (!streams)
		return;

	for (i = 0; i < nr_streams; i++)
		destroy_client_stream(&streams[i]);

	free(streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

__hot
struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_pop_stack16(&cs->stack, &idx);
	if (unlikely(ret))
		return GWHF_ERR_PTR(ret);

	cl = &cs->clients[idx];
	ret = init_client_streams(cl);
	if (unlikely(ret))
		goto out_err;

	return cl;

out_err:
	gwhf_push_stack16(&cs->stack, idx);
	return GWHF_ERR_PTR(ret);
}

void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx;
	int err;

	gwhf_reset_client(cl);
	idx = (uint16_t)(cl - cs->clients);
	err = gwhf_push_stack16(&cs->stack, idx);
	assert(err == 0);
	(void)err;
}

void gwhf_reset_client(struct gwhf_client *cl)
{
	if (cl->fd >= 0) {
		close(cl->fd);
		cl->fd = -1;
	}

	destroy_client_streams(cl);
}

static int consume_http_req_hdr(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = &cl->streams[0];
	struct gwhf_http_req_hdr *hdr = &str->req_hdr;
	uint32_t hdr_len;
	size_t len;
	char *buf;
	int ret;

	assert(str->total_req_body_len == 0);
	assert(hdr->content_length == GWHF_HTTP_CONLEN_UNINITIALIZED);

	buf = str->req_buf;
	len = str->req_buf_len;
	ret = gwhf_parse_http_req_hdr(buf, len, hdr);
	if (unlikely(ret < 0))
		return ret;

	hdr_len = (uint32_t)ret;

	/*
	 * If @len > @hdr_len, then the request body is also received.
	 * Move the request body to the beginning of the buffer and
	 * update the buffer length.
	 */
	if (len > hdr_len) {
		str->req_buf_len = len - hdr_len;
		memmove(buf, buf + hdr_len, str->req_buf_len);
	} else {
		str->req_buf_len = 0;
	}

	str->state = T_CL_STREAM_ROUTE_HEADER;
	ret = gwhf_consume_client_recv_buf(ctx, cl);
	if (unlikely(ret < 0))
		return ret;

	str->total_req_body_len += (int64_t)str->req_buf_len;
	str->state = T_CL_STREAM_RECV_BODY;
	return gwhf_consume_client_recv_buf(ctx, cl);
}

static int route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = &cl->streams[0];
	int ret;

	ret = gwhf_exec_route_header(ctx, cl);
	if (unlikely(ret < 0))
		return ret;

	str->state = T_CL_STREAM_RECV_BODY;
	return gwhf_consume_client_recv_buf(ctx, cl);
}

static int consume_http_req_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = &cl->streams[0];
	struct gwhf_http_req_hdr *hdr = &str->req_hdr;
	int64_t ctlen = hdr->content_length;

	assert(ctlen != GWHF_HTTP_CONLEN_UNINITIALIZED);

	if (ctlen == GWHF_HTTP_CONLEN_CHUNKED ||
	    ctlen == GWHF_HTTP_CONLEN_INVALID)
		return -EINVAL;

	if (ctlen >= 0 && str->total_req_body_len > ctlen)
		return -EINVAL;

	if (str->total_req_body_len == ctlen ||
	    ctlen == GWHF_HTTP_CONLEN_NONE) {
		str->state = T_CL_STREAM_ROUTE_BODY;
		return gwhf_consume_client_recv_buf(ctx, cl);
	}

	return -EAGAIN;
}

static int route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	return gwhf_exec_route_body(ctx, cl);
}

static int realloc_stream_buffer_if_needed(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = &cl->streams[0];
	uint32_t free_buf_len;
	uint32_t new_alloc;
	char *new_buf;

	free_buf_len = str->req_buf_alloc - str->req_buf_len;
	if (free_buf_len)
		return -EAGAIN;

	new_alloc = (str->req_buf_alloc + 1u) * 2u;
	if (unlikely(new_alloc > 65536u*2u))
		return -ENOMEM;

	new_buf = realloc(str->req_buf, new_alloc);
	if (unlikely(!new_buf))
		return -ENOMEM;

	str->req_buf = new_buf;
	str->req_buf_alloc = new_alloc;
	return -EAGAIN;
}

int gwhf_consume_client_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = &cl->streams[0];
	int ret = 0;

	assert(str->state != T_CL_STREAM_OFF);

	switch (str->state) {
	case T_CL_STREAM_IDLE:
	case T_CL_STREAM_RECV_HEADER:
		printf("T_CL_STREAM_RECV_HEADER\n");
		ret = consume_http_req_hdr(ctx, cl);
		break;
	case T_CL_STREAM_ROUTE_HEADER:
		printf("T_CL_STREAM_ROUTE_HEADER\n");
		ret = route_header(ctx, cl);
		break;
	case T_CL_STREAM_RECV_BODY:
		printf("T_CL_STREAM_RECV_BODY\n");
		ret = consume_http_req_body(ctx, cl);
		break;
	case T_CL_STREAM_ROUTE_BODY:
		printf("T_CL_STREAM_ROUTE_BODY\n");
		ret = route_body(ctx, cl);
		break;
	}

	if (ret == -EAGAIN)
		return realloc_stream_buffer_if_needed(cl);

	return ret;
}

int gwhf_get_client_send_buf(struct gwhf *ctx, struct gwhf_client *cl,
			     const void **buf, size_t *len)
{
	static const char res[] = "HTTP/1.1 200 OK\r\n"
				  "Content-Length: 13\r\n"
				  "Connection: keep-alive\r\n"
				  "\r\n"
				  "Hello World!\n";

	if (cl->streams[0].state == T_CL_STREAM_SEND_HEADER) {
		*buf = res;
		*len = sizeof(res) - 1;
		cl->streams[0].state = T_CL_STREAM_SEND_BODY;
		return 0;
	}

	if (cl->streams[0].state == T_CL_STREAM_SEND_BODY) {
		*buf = NULL;
		*len = 0;
		cl->streams[0].state = T_CL_STREAM_IDLE;
		cl->streams[0].req_buf_len = 0;
		cl->streams[0].total_req_body_len = 0;
		gwhf_destroy_http_req_hdr(&cl->streams[0].req_hdr);
		gwhf_destroy_http_res_hdr(&cl->streams[0].res_hdr);
		return 0;
	}

	return -EAGAIN;
}

void gwhf_client_send_buf_advance(struct gwhf_client *cl, size_t len)
{
	(void)cl;
	(void)len;
}
