// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./stream.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static int init_stream_buf(struct gwhf_client_stream_buf *csb)
{
	csb->buf = malloc(4096);
	if (!csb->buf)
		return -ENOMEM;

	csb->alloc = 4096;
	csb->len = 0;
	return 0;
}

static void destroy_stream_buf(struct gwhf_client_stream_buf *csb)
{
	if (!csb->buf)
		return;

	free(csb->buf);
	csb->buf = NULL;
	memset(csb, 0, sizeof(*csb));
}

int gwhf_stream_init(struct gwhf_client_stream *str)
{
	int ret;

	ret = init_stream_buf(&str->req_buf);
	if (ret)
		return ret;

	ret = init_stream_buf(&str->res_buf);
	if (ret)
		goto out_req_buf;

	ret = gwhf_http_req_init(&str->req);
	if (ret)
		goto out_res_buf;

	ret = gwhf_http_res_init(&str->res);
	if (ret)
		goto out_req;

	str->sent_len = 0;
	str->state = TCL_IDLE;
	return 0;

out_req:
	gwhf_http_req_destroy(&str->req);
out_res_buf:
	destroy_stream_buf(&str->res_buf);
out_req_buf:
	destroy_stream_buf(&str->req_buf);
	return ret;
}

int gwhf_stream_init_all(struct gwhf_client *cl, uint32_t nr_streams)
{
	struct gwhf_client_stream *streams;
	uint32_t i;
	int ret;

	streams = calloc(nr_streams, sizeof(*streams));
	if (!streams)
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		ret = gwhf_stream_init(&streams[i]);
		if (ret)
			goto out_err;
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	cl->cur_stream = 0;
	return 0;

out_err:
	while (i--)
		gwhf_stream_destroy(&streams[i]);

	free(streams);
	return ret;
}

void gwhf_stream_destroy_all(struct gwhf_client *cl)
{
	uint32_t i = cl->nr_streams;

	if (!cl->streams)
		return;

	while (i--)
		gwhf_stream_destroy(&cl->streams[i]);

	free(cl->streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

void gwhf_stream_destroy(struct gwhf_client_stream *str)
{
	destroy_stream_buf(&str->req_buf);
	destroy_stream_buf(&str->res_buf);
	gwhf_http_req_destroy(&str->req);
	gwhf_http_res_destroy(&str->res);
}

static int realloc_stream_buf_if_needed(struct gwhf_client_stream_buf *sb,
					size_t add_len)
{
	size_t new_alloc;
	size_t new_len;
	char *new_buf;

	new_len = sb->len + add_len;
	if (new_len <= sb->alloc)
		return 0;

	new_alloc = new_len + 8192;
	if (unlikely(new_alloc > UINT32_MAX))
		return -ENOMEM;

	new_buf = realloc(sb->buf, new_alloc);
	if (unlikely(!new_buf))
		return -ENOMEM;

	sb->buf = new_buf;
	sb->alloc = new_alloc;
	return 0;
}

int gwhf_stream_append_buf(struct gwhf_client_stream_buf *sb, const void *buf,
			   size_t len)
{
	int ret;

	ret = realloc_stream_buf_if_needed(sb, len);
	if (unlikely(ret < 0))
		return ret;

	memcpy(sb->buf + sb->len, buf, len);
	sb->len += len;
	return 0;
}

void gwhf_stream_consume_buf(struct gwhf_client_stream_buf *sb, size_t len)
{
	assert(len <= sb->len);
	memmove(sb->buf, sb->buf + len, sb->len - len);
	sb->len -= len;
}

static int realloc_raw_stream_buf_if_needed(struct gwhf_raw_buf *rbuf,
					    size_t add_len)
{
	size_t new_alloc;
	size_t new_len;
	char *new_buf;

	new_len = rbuf->len + add_len;
	if (new_len <= rbuf->alloc)
		return 0;

	new_alloc = new_len + 8192;
	if (unlikely(new_alloc > UINT32_MAX))
		return -ENOMEM;

	new_buf = realloc(rbuf->buf, new_alloc);
	if (unlikely(!new_buf))
		return -ENOMEM;

	rbuf->buf = new_buf;
	rbuf->alloc = new_alloc;
	return 0;
}

int gwhf_stream_append_raw_buf(struct gwhf_raw_buf *rbuf, const void *buf,
			       size_t len)
{
	int ret;

	ret = realloc_raw_stream_buf_if_needed(rbuf, len);
	if (unlikely(ret < 0))
		return ret;

	memcpy(rbuf->buf + rbuf->len, buf, len);
	rbuf->len += len;
	return 0;
}

void gwhf_stream_consume_raw_buf(struct gwhf_raw_buf *rbuf, size_t len)
{
	assert(len <= rbuf->len);
	memmove(rbuf->buf, rbuf->buf + len, rbuf->len - len);
	rbuf->len -= len;
}
