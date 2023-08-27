// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./client.h"
#include "./stream.h"
#include "./internal.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static int consume_recv_buf(struct gwhf *ctx, struct gwhf_client *cl);

static int consume_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_http_req_hdr *hdr = &str->req.hdr;
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	assert(str->req.hdr.content_length == GWHF_CONLEN_UNSET);
	ret = gwhf_http_req_parse_header(hdr, rb);
	if (unlikely(ret < 0))
		return ret;

	gwhf_buf_advance(rb, ret);
	str->state = TCL_ROUTE_HEADER;
	return consume_recv_buf(ctx, cl);
}

static int consume_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_http_req_hdr *hdr = &str->req.hdr;
	struct gwhf_buf *rb = &str->req_buf;
	int64_t conlen = hdr->content_length;
	int ret;

	assert(conlen != GWHF_CONLEN_UNSET);

	if (unlikely(conlen == GWHF_CONLEN_INVALID))
		return -EINVAL;

	/*
	 * TODO(ammarfaizi2): Add support for chunked transfer encoding.
	 */
	if (conlen == GWHF_CONLEN_CHUNKED)
		return -EOPNOTSUPP;

	ret = gwhf_http_req_body_add(&str->req, rb->buf, rb->len);
	if (unlikely(ret < 0))
		return ret;

	if (conlen == GWHF_CONLEN_NOT_PRESENT) {
		if (str->req.body_len > 0) {
			/*
			 * TODO(ammarfaizi2):
		 	 * Could thos be pipelined request? Investigate this
			 * later.
			 */
			return -EINVAL;
		}

		goto out;
	}

	if (conlen > (int64_t)str->req.body_len) {
		/*
		 * If the received body is smaller than the content length,
		 * then we need to receive more data.
		 */
		return -EAGAIN;
	}

	if (conlen < (int64_t)str->req.body_len) {
		/*
		 * If the received body is larger than the content length, then
		 * we assume it's invalid.
		 *
		 * TODO(ammarfaizi2):
		 * Could thos be pipelined request? Investigate this later.
		 */
		return -EINVAL;
	}

out:
	str->state = TCL_ROUTE_BODY;
	return consume_recv_buf(ctx, cl);
}

static int route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	int ret;

	ret = gwhf_route_exec_on_header(ctx, cl);
	if (unlikely(ret != GWHF_ROUTE_CONTINUE))
		return ret;

	str->state = TCL_RECV_BODY;
	return consume_recv_buf(ctx, cl);
}

static int route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = gwhf_route_exec_on_body(ctx, cl);
	if (unlikely(ret != GWHF_ROUTE_CONTINUE))
		return ret;

	return 0;
}

static int consume_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	int ret;

	switch (str->state) {
	case TCL_IDLE:
	case TCL_RECV_HEADER:
		ret = consume_header(ctx, cl);
		break;
	case TCL_ROUTE_HEADER:
		ret = route_header(ctx, cl);
		break;
	case TCL_RECV_BODY:
		ret = consume_body(ctx, cl);
		break;
	case TCL_ROUTE_BODY:
		ret = route_body(ctx, cl);
		break;
	default:
		assert(0);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void init_client_first(struct gwhf_client *cl)
{
#ifdef _WIN32
	cl->fd.fd = INVALID_SOCKET;
#else
	cl->fd.fd = -1;
#endif
}

static void reset_client(struct gwhf_client *cl)
{
	gwhf_sock_close(&cl->fd);
	gwhf_buf_destroy(&cl->raw_recv_buf);
	gwhf_buf_destroy(&cl->raw_send_buf);
	gwhf_stream_destroy_all(cl);
	cl->pollout_set = false;
}

__cold
int gwhf_client_init_slot(struct gwhf_client_slot *cs, uint32_t max_clients)
{
	uint16_t i;
	int ret;

	ret = gwhf_stack16_init(&cs->stack, max_clients);
	if (ret)
		return ret;

	cs->clients = calloc(max_clients, sizeof(*cs->clients));
	if (!cs->clients) {
		gwhf_stack16_destroy(&cs->stack);
		return -ENOMEM;
	}

	i = max_clients;
	while (i--) {
		init_client_first(&cs->clients[i]);
		__gwhf_stack16_push(&cs->stack, i);
	}

	return 0;
}

__cold
void gwhf_client_destroy_slot(struct gwhf_client_slot *cs)
{
	uint16_t i;

	if (!cs->clients)
		return;

	i = cs->stack.size;
	while (i--)
		reset_client(&cs->clients[i]);

	free(cs->clients);
	gwhf_stack16_destroy(&cs->stack);
}

__hot
struct gwhf_client *gwhf_client_get(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_stack16_pop(&cs->stack, &idx);
	if (unlikely(ret))
		return GWHF_ERR_PTR(ret);

	cl = &cs->clients[idx];

	ret = gwhf_buf_init(&cl->raw_recv_buf);
	if (unlikely(ret))
		goto out_put;

	ret = gwhf_buf_init_len(&cl->raw_send_buf, 128);
	if (unlikely(ret))
		goto out_recv_buf;

	ret = gwhf_stream_init_all(cl, 1);
	if (unlikely(ret))
		goto out_send_buf;

	return cl;

out_send_buf:
	gwhf_buf_destroy(&cl->raw_send_buf);
out_recv_buf:
	gwhf_buf_destroy(&cl->raw_recv_buf);
out_put:
	gwhf_stack16_push(&cs->stack, idx);
	return GWHF_ERR_PTR(ret);
}

__hot
void gwhf_client_put(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx;

	idx = cl - cs->clients;
	assert(idx < cs->stack.size);

	reset_client(cl);
	gwhf_stack16_push(&cs->stack, idx);
}

__hot
int gwhf_client_get_recv_buf(struct gwhf_client *cl, void **buf_p, size_t *len_p)
{
	struct gwhf_buf *rrb = &cl->raw_recv_buf;
	uint32_t avail;
	int ret;

	avail = gwhf_buf_get_free_space(rrb);
	if (avail <= 1) {
		ret = gwhf_buf_add_alloc(rrb, 4096);
		if (ret)
			return ret;

		avail = gwhf_buf_get_free_space(rrb);
	}

	*buf_p = rrb->buf + rrb->len;
	*len_p = avail - 1;
	return 0;
}

__hot
void gwhf_client_advance_recv_buf(struct gwhf_client *cl, size_t len)
{
	struct gwhf_buf *rrb = &cl->raw_recv_buf;

	assert(len < gwhf_buf_get_free_space(rrb));
	rrb->len += (uint32_t)len;
	rrb->buf[rrb->len] = '\0';
}

__hot
int gwhf_client_consume_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_buf *rrb = &cl->raw_recv_buf;
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	ret = gwhf_buf_append(rb, rrb->buf, rrb->len);
	if (ret < 0)
		return ret;

	return consume_recv_buf(ctx, cl);
}

static int handle_keep_alive(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);

	if (gwhf_client_should_be_kept_alive(cl)) {
		int ret;

		gwhf_stream_destroy(str);
		ret = gwhf_stream_init(str);
		if (ret < 0) {
			str->state = TCL_CLOSE;
			return ret;
		}

		str->state = TCL_IDLE;
		return 0;
	}

	str->state = TCL_CLOSE;
	return -ECONNRESET;
}

__hot
int gwhf_client_get_send_buf(struct gwhf_client *cl, const void **buf, size_t *len)
{
	int ret;

	if (!cl->raw_send_buf.len) {
		ret = handle_keep_alive(cl);
		if (ret < 0)
			return ret;

		return -ENOBUFS;
	}

	*buf = cl->raw_send_buf.buf;
	*len = (size_t)cl->raw_send_buf.len;
	return 0;
}

__hot
void gwhf_client_advance_send_buf(struct gwhf_client *cl, size_t len)
{
	struct gwhf_buf *sb = &cl->raw_send_buf;
	size_t new_len;

	new_len = sb->len - len;
	assert(len <= cl->raw_send_buf.len);

	if (new_len) {
		memmove(sb->buf, sb->buf + len, new_len);
		sb->len = new_len;
	} else {
		sb->len = 0;
	}
}

__hot
bool gwhf_client_has_send_buf(struct gwhf_client *cl)
{
	return (cl->raw_send_buf.len > 0);
}

bool gwhf_client_should_be_kept_alive(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	const char *tmp;

	tmp = gwhf_http_req_get_hdr(&str->req, "connection");
	if (tmp)
		return !gwhf_strcmpi(tmp, "keep-alive");

	tmp = gwhf_http_req_get_version(&str->req);
	if (!strcmp(tmp, "HTTP/1.1"))
		return true;

	return false;
}

bool gwhf_client_need_keep_alive_hdr(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);

	if (gwhf_http_res_get_hdr(&str->res, "connection"))
		return false;

	return gwhf_client_should_be_kept_alive(cl);
}
