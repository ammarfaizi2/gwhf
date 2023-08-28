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

static void init_client_first(struct gwhf_client *cl)
{
#ifdef _WIN32
	cl->fd.fd = INVALID_SOCKET;
#else
	cl->fd.fd = -1;
#endif

#ifdef CONFIG_HTTPS
	cl->ssl = NULL;
	cl->rbio = NULL;
	cl->wbio = NULL;
	cl->https_state = GWHF_CL_HTTPS_UNSET;
#endif
}

static void reset_client(struct gwhf_client *cl)
{
	gwhf_sock_close(&cl->fd);
	gwhf_buf_destroy(&cl->raw_recv_buf);
	gwhf_buf_destroy(&cl->raw_send_buf);
	gwhf_stream_destroy_all(cl);
#ifdef CONFIG_HTTPS
	gwhf_ssl_destroy_client(cl);
	cl->https_state = GWHF_CL_HTTPS_UNSET;
#endif
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

#ifdef CONFIG_HTTPS
	assert(!cl->ssl);
	assert(!cl->rbio);
	assert(!cl->wbio);
#endif

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

static int extract_raw_no_ssl(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_buf *rrb = &cl->raw_recv_buf;
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	ret = gwhf_buf_append(rb, rrb->buf, rrb->len);
	if (ret < 0)
		return ret;

	gwhf_buf_advance(rrb, rrb->len);
	return 0;
}

#ifdef CONFIG_HTTPS
static int ssl_read_to_stream(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	ret = SSL_read(cl->ssl, rb->buf + rb->len, rb->alloc - rb->len - 1);
	if (ret <= 0) {
		ret = SSL_get_error(cl->ssl, ret);
		switch (ret) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_X509_LOOKUP:
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_RETRY_VERIFY:
		case SSL_ERROR_WANT_ACCEPT:
			return -EAGAIN;
		default:
			return -EIO;
		}
	}

	rb->len += ret;
	rb->buf[rb->len] = '\0';
	return 0;
}

static int extract_raw_ssl(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_buf *rrb = &cl->raw_recv_buf;
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	assert(cl->ssl);
	assert(cl->rbio);
	assert(cl->wbio);

	ret = BIO_write(cl->rbio, rrb->buf, rrb->len);
	if (ret <= 0)
		return -EIO;

	gwhf_buf_advance(rrb, ret);
	ret = gwhf_buf_realloc_if_needed(rb, rb->len + (size_t)ret + 1);
	if (ret < 0)
		return ret;

	return ssl_read_to_stream(cl);
}

static int do_tls_handshake(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_buf *rrb = &cl->raw_recv_buf;
	struct gwhf_buf *rsb = &cl->raw_send_buf;
	int ret, wr_ret;

	if (!cl->ssl) {
		ret = gwhf_ssl_init_client(ctx, cl);
		if (ret < 0)
			return ret;
	}

	ret = BIO_write(cl->rbio, rrb->buf, rrb->len);
	if (ret <= 0)
		return -EIO;

	wr_ret = ret;
	ret = SSL_do_handshake(cl->ssl);
	if (ret == 1) {
		gwhf_buf_advance(rrb, wr_ret);
		cl->https_state = GWHF_CL_HTTPS_ON;
		goto out;
	}

	ret = SSL_get_error(cl->ssl, ret);
	switch (ret) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_RETRY_VERIFY:
	case SSL_ERROR_WANT_ACCEPT:
		gwhf_buf_advance(rrb, wr_ret);
		break;
	default:
		gwhf_ssl_destroy_client(cl);
		cl->https_state = GWHF_CL_HTTPS_OFF;
		return extract_raw_no_ssl(cl);
	}

out:
	ret = gwhf_buf_realloc_if_needed(rsb, 8192);
	if (ret < 0)
		return ret;

	ret = BIO_read(cl->wbio, rsb->buf + rsb->len, rsb->alloc - rsb->len);
	if (ret <= 0)
		return -EIO;

	rsb->len += ret;

	if (cl->https_state == GWHF_CL_HTTPS_ON)
		return ssl_read_to_stream(cl);

	return -EAGAIN;
}

static int extract_raw_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	switch (cl->https_state) {
	case GWHF_CL_HTTPS_UNSET:
		return do_tls_handshake(ctx, cl);
	case GWHF_CL_HTTPS_ON:
		return extract_raw_ssl(cl);
	case GWHF_CL_HTTPS_OFF:
		return extract_raw_no_ssl(cl);
	default:
		assert(0);
		abort();
	}
}
#else /* #ifdef CONFIG_HTTPS */
static int extract_raw_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	(void)ctx;
	return extract_raw_no_ssl(cl);
}
#endif /* #ifdef CONFIG_HTTPS */

__hot
int gwhf_client_consume_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = extract_raw_recv_buf(ctx, cl);
	if (ret < 0)
		return ret;

	return gwhf_stream_consume_request(ctx, cl);
}

#if 0
static int handle_keep_alive(struct gwhf_client *cl)
{
	struct gwhf_client_stream *str;

#ifdef CONFIG_HTTPS
	if (cl->https_state == GWHF_CL_HTTPS_UNSET)
		return 0;
#endif

	str = gwhf_client_get_cur_stream(cl);
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
#endif

__hot
int gwhf_client_get_send_buf(struct gwhf_client *cl, const void **buf, size_t *len)
{
	int ret;

	if (!cl->raw_send_buf.len)
		return -ENOBUFS;

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
		struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);

		sb->len = 0;
		gwhf_stream_destroy(str);
		if (gwhf_stream_init(str) < 0)
			str->state = TCL_CLOSE;
		else
			str->state = TCL_IDLE;
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
