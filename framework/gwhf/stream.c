// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <assert.h>

#include "http/response.h"
#include "http/request.h"
#include "stream.h"

static void gwhf_destroy_client_stream_buf(struct gwhf_client_stream_buf *buf)
{
	if (buf->buf) {
		free(buf->buf);
	} else {
		assert(!buf->alloc);
		assert(!buf->len);
	}
}

void gwhf_destroy_client_stream(struct gwhf_client_stream *cs)
{
	gwhf_destroy_client_stream_buf(&cs->req_buf);
	gwhf_destroy_client_stream_buf(&cs->res_buf);
	gwhf_http_req_destroy(&cs->req);
	gwhf_http_res_destroy(&cs->res);
	cs->sent_len = 0;
}

void gwhf_destroy_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams = cl->streams;
	uint32_t nr_streams = cl->nr_streams;
	uint32_t i;

	for (i = 0; i < nr_streams; i++)
		gwhf_destroy_client_stream(&streams[i]);

	free(streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

static int gwhf_init_client_stream_buf(struct gwhf_client_stream_buf *sbuf)
{
	char *buf;

	buf = calloc(1, 4096);
	if (unlikely(!buf))
		return -ENOMEM;

	sbuf->buf = buf;
	sbuf->len = 0;
	sbuf->alloc = 4096;
	return 0;
}

int gwhf_init_client_stream(struct gwhf_client_stream *cs)
{
	int ret;

	ret = gwhf_init_client_stream_buf(&cs->req_buf);
	if (unlikely(ret))
		return ret;

	ret = gwhf_init_client_stream_buf(&cs->res_buf);
	if (unlikely(ret))
		goto out_req_buf;

	ret = gwhf_http_req_init(&cs->req);
	if (unlikely(ret))
		goto out_res_buf;

	ret = gwhf_http_res_init(&cs->res);
	if (unlikely(ret))
		goto out_req;

	cs->sent_len = 0;
	return 0;

out_req:
	gwhf_http_req_destroy(&cs->req);
out_res_buf:
	gwhf_destroy_client_stream_buf(&cs->res_buf);
out_req_buf:
	gwhf_destroy_client_stream_buf(&cs->req_buf);
	return ret;
}

int gwhf_init_client_streams(struct gwhf_client *cl, uint32_t nr_streams)
{
	struct gwhf_client_stream *streams;
	uint32_t i;
	int ret;

	streams = calloc(nr_streams, sizeof(*streams));
	if (unlikely(!streams))
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		ret = gwhf_init_client_stream(&streams[i]);
		if (likely(!ret))
			continue;

		while (i--)
			gwhf_destroy_client_stream(&streams[i]);

		free(streams);
		return ret;
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	cl->cur_stream = 0;
	return 0;
}

static int __gwhf_init_client_ssl_buf(struct gwhf_ssl_buffer *sbuf)
{
	char *buf;

	buf = calloc(1, 4096);
	if (unlikely(!buf))
		return -ENOMEM;

	sbuf->buf = buf;
	sbuf->len = 0;
	sbuf->alloc = 4096;
	return 0;
}

static void __gwhf_destroy_client_ssl_buf(struct gwhf_ssl_buffer *sbuf)
{
	if (sbuf->buf) {
		free(sbuf->buf);
	} else {
		assert(!sbuf->alloc);
		assert(!sbuf->len);
	}
}

int gwhf_init_client_ssl_buf(struct gwhf_client *cl)
{
	int ret;

	ret = __gwhf_init_client_ssl_buf(&cl->ssl_req_buf);
	if (unlikely(ret))
		return ret;

	ret = __gwhf_init_client_ssl_buf(&cl->ssl_res_buf);
	if (unlikely(ret)) {
		__gwhf_destroy_client_ssl_buf(&cl->ssl_req_buf);
		return ret;
	}

	return 0;
}

void gwhf_destroy_client_ssl_buf(struct gwhf_client *cl)
{
	__gwhf_destroy_client_ssl_buf(&cl->ssl_req_buf);
	__gwhf_destroy_client_ssl_buf(&cl->ssl_res_buf);
}
