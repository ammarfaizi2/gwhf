// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./stream.h"
#include "./buf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int gwhf_stream_init(struct gwhf_client_stream *str)
{
	int ret;

	ret = gwhf_buf_init(&str->req_buf);
	if (ret)
		return ret;

	ret = gwhf_buf_init(&str->res_buf);
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
	gwhf_buf_destroy(&str->res_buf);
out_req_buf:
	gwhf_buf_destroy(&str->req_buf);
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
	gwhf_buf_destroy(&str->req_buf);
	gwhf_buf_destroy(&str->res_buf);
	gwhf_http_req_destroy(&str->req);
	gwhf_http_res_destroy(&str->res);
}

static int stream_consume_request(struct gwhf *ctx, struct gwhf_client *cl);

static int consume_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	assert(str->req.hdr.content_length == GWHF_CONLEN_UNSET);
	ret = gwhf_http_req_parse_header(&str->req.hdr, rb);
	if (ret < 0)
		return ret;

	gwhf_buf_advance(rb, ret);
	str->state = TCL_ROUTE_HEADER;
	return stream_consume_request(ctx, cl);
}

static int validate_content_length(int64_t conlen)
{
	assert(conlen != GWHF_CONLEN_UNSET);

	if (unlikely(conlen == GWHF_CONLEN_INVALID))
		return -EINVAL;

	/*
	 * TODO(ammarfaizi2):
	 * Add support for chunked transfer encoding.
	 */
	if (conlen == GWHF_CONLEN_CHUNKED)
		return -EOPNOTSUPP;

	return 0;
}

static int consume_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	int64_t conlen = str->req.hdr.content_length;
	struct gwhf_buf *rb = &str->req_buf;
	int ret;

	ret = validate_content_length(conlen);
	if (ret < 0)
		return ret;

	if (rb->len) {
		ret = gwhf_http_req_body_add(&str->req, rb->buf, rb->len);
		if (ret < 0)
			return ret;

		gwhf_buf_advance(rb, rb->len);
	}

	str->state = TCL_ROUTE_BODY;
	return stream_consume_request(ctx, cl);
}

static int route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	int ret;

	ret = gwhf_route_exec_on_header(ctx, cl);
	if (ret != GWHF_ROUTE_CONTINUE)
		return ret;

	str->state = TCL_RECV_BODY;
	return stream_consume_request(ctx, cl);
}

static int route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = gwhf_route_exec_on_body(ctx, cl);
	if (ret != GWHF_ROUTE_CONTINUE)
		return ret;

	return 0;
}

static int stream_consume_request(struct gwhf *ctx, struct gwhf_client *cl)
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

int gwhf_stream_consume_request(struct gwhf *ctx, struct gwhf_client *cl)
{
	return stream_consume_request(ctx, cl);
}
