
#include "http/response.h"
#include "http/request.h"
#include "stream.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int gwhf_init_client_stream(struct gwhf_client_stream *stream)
{
	int ret;
	stream->state = T_CL_STREAM_IDLE;
	stream->err_str = NULL;

	ret = gwhf_init_http_req_hdr(&stream->req_hdr);
	if (unlikely(ret))
		return ret;

	ret = gwhf_init_http_res_hdr(&stream->res_hdr);
	if (unlikely(ret))
		goto out_req_hdr;

	ret = gwhf_init_http_res_body(&stream->res_body);
	if (unlikely(ret))
		goto out_res_hdr;

	ret = gwhf_init_req_buf(&stream->req_buf);
	if (unlikely(ret))
		goto out_res_body;

	ret = gwhf_init_res_buf(&stream->res_buf);
	if (unlikely(ret))
		goto out_req_buf;

	return 0;

out_req_buf:
	gwhf_destroy_req_buf(&stream->req_buf);
out_res_body:
	gwhf_destroy_http_res_body(&stream->res_body);
out_res_hdr:
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
out_req_hdr:
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
	return ret;
}

static void gwhf_destroy_client_stream(struct gwhf_client_stream *stream)
{
	if (stream->err_str) {
		free(stream->err_str);
		stream->err_str = NULL;
	}

	gwhf_destroy_req_buf(&stream->req_buf);
	gwhf_destroy_res_buf(&stream->res_buf);
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
	gwhf_destroy_http_res_body(&stream->res_body);
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
}

__cold
void gwhf_destroy_client_streams(struct gwhf_client *cl)
{
	uint32_t i;

	if (!cl->streams)
		return;

	for (i = 0; i < cl->nr_streams; i++)
		gwhf_destroy_client_stream(&cl->streams[i]);

	free(cl->streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
	cl->cur_stream = 0;
}

__hot
int gwhf_init_client_streams(struct gwhf_client *cl, uint32_t nr_streams)
{
	struct gwhf_client_stream *streams;
	uint32_t i;

	assert(!cl->streams);
	assert(!cl->nr_streams);

	streams = calloc(nr_streams, sizeof(*streams));
	if (!streams)
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		int ret;

		ret = gwhf_init_client_stream(&streams[i]);
		if (ret) {
			while (i--)
				gwhf_destroy_client_stream(&streams[i]);
			free(streams);
			return ret;
		}
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	cl->cur_stream = 0;
	return 0;
}

static void gwhf_soft_reset_client_stream(struct gwhf_client_stream *stream)
{
	gwhf_destroy_req_buf(&stream->req_buf);
	gwhf_destroy_res_buf(&stream->res_buf);
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
	gwhf_destroy_http_res_body(&stream->res_body);
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
	stream->state = T_CL_STREAM_IDLE;

	if (stream->err_str) {
		free(stream->err_str);
		stream->err_str = NULL;
	}
}

__hot
void gwhf_soft_reset_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint32_t i;

	assert(cl->streams);
	assert(cl->nr_streams);

	streams = cl->streams;
	for (i = 0; i < cl->nr_streams; i++)
		gwhf_soft_reset_client_stream(&streams[i]);
}

__hot
int gwhf_get_recv_buffer(struct gwhf_client *cl, void **buf_p, size_t *len_p)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	size_t available;

	available = stream->req_buf.buf_alloc - stream->req_buf.buf_len;
	if (unlikely(!available)) {
		const uint32_t max_alloc = 65536u * 4u;
		uint32_t new_alloc;
		char *tmp;

		new_alloc = stream->req_buf.buf_alloc + 8192u;
		if (new_alloc > max_alloc)
			return -ENOMEM;

		tmp = realloc(stream->req_buf.buf, new_alloc);
		if (!tmp)
			return -ENOMEM;

		stream->req_buf.buf = tmp;
		stream->req_buf.buf_alloc = new_alloc;
		available = new_alloc - stream->req_buf.buf_len;
	}

	*buf_p = stream->req_buf.buf + stream->req_buf.buf_len;
	*len_p = available - 1u; /* min 1u for '\0' when advance the buf. */
	return 0;
}

__hot
void gwhf_advance_recv_buffer(struct gwhf_client *cl, size_t len)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	size_t available;

	available = stream->req_buf.buf_alloc - stream->req_buf.buf_len;
	assert(len <= available);

	stream->req_buf.buf_len += len;
	stream->req_buf.buf[stream->req_buf.buf_len] = '\0';
}

static int consume_stream_buf(struct gwhf *ctx, struct gwhf_client *cl);

static int process_req_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_http_req_hdr *hdr = &stream->req_hdr;
	size_t len = stream->req_buf.buf_len;
	char *buf = stream->req_buf.buf;
	size_t hdr_len;
	int ret;

	assert(!stream->req_buf.total_req_body_len);
	assert(hdr->content_length == GWHF_HTTP_CONLEN_UNINITIALIZED);

	ret = gwhf_parse_http_req_hdr(buf, len, hdr);
	if (unlikely(ret < 0)) {
		if (ret == -EAGAIN)
			return 0;

		stream->err_str = strdup("Failed to parse HTTP request header");
		if (!stream->err_str)
			return -ENOMEM;

		stream->state = T_CL_STREAM_ERROR;
		return 0;
	}

	hdr_len = (size_t)ret;
	if (len > hdr_len) {
		/*
		 * If we have more data than the header length, that means
		 * we have the request body as well. Move the body to the
		 * beginning of the buffer and update the buffer length.
		 */
		const char *src = buf + hdr_len;
		char *dst = stream->req_buf.buf;
		size_t cp_len = len - hdr_len;

		memmove(dst, src, cp_len);
		stream->req_buf.buf_len = cp_len;
		stream->req_buf.total_req_body_len = cp_len;
	} else {
		stream->req_buf.buf_len = 0;
	}

	stream->state = T_CL_STREAM_ROUTE_HEADER;
	return consume_stream_buf(ctx, cl);
}

static int route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	int ret;

	ret = gwhf_exec_route_header(ctx, cl);
	if (unlikely(ret))
		return ret;

	stream->state = T_CL_STREAM_RECV_BODY;
	return consume_stream_buf(ctx, cl);
}

static int process_req_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	int64_t conlen = stream->req_hdr.content_length;

	assert(conlen != GWHF_HTTP_CONLEN_UNINITIALIZED);

	if (conlen == GWHF_HTTP_CONLEN_INVALID) {
		stream->err_str = strdup("Invalid Content-Length");
		if (!stream->err_str)
			return -ENOMEM;

		stream->state = T_CL_STREAM_ERROR;
		return 0;
	}

	stream->req_buf.total_req_body_len += (int64_t)stream->req_buf.buf_len;

	if (conlen == GWHF_HTTP_CONLEN_NONE) {
		stream->state = T_CL_STREAM_ROUTE_BODY;
		goto out_route;
	}

	if (conlen == GWHF_HTTP_CONLEN_CHUNKED) {
		/*
		 * TODO(ammarfaizi2): Support chunked request body.
		 */
		stream->err_str = strdup("Chunked request body not supported");
		if (!stream->err_str)
			return -ENOMEM;

		stream->state = T_CL_STREAM_ERROR;
		return 0;
	}

	if (stream->req_buf.total_req_body_len < conlen)
		return 0;

	if (stream->req_buf.total_req_body_len > conlen) {
		stream->err_str = strdup("Content-Length does not match the actual body length");
		if (!stream->err_str)
			return -ENOMEM;

		stream->state = T_CL_STREAM_ERROR;
		return 0;
	}

out_route:
	stream->state = T_CL_STREAM_ROUTE_BODY;
	return consume_stream_buf(ctx, cl);
}

static int route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	int ret;

	ret = gwhf_exec_route_body(ctx, cl);
	if (unlikely(ret))
		return ret;

	ret = gwhf_construct_response(cl);
	if (unlikely(ret))
		return ret;

	stream->state = T_CL_STREAM_SEND_HEADER;
	return 0;
}

static int consume_stream_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	uint8_t state = cl->streams[cl->cur_stream].state;
	int ret;

	switch (state) {
	case T_CL_STREAM_IDLE:
	case T_CL_STREAM_RECV_HEADER:
		ret = process_req_header(ctx, cl);
		break;
	case T_CL_STREAM_ROUTE_HEADER:
		ret = route_header(ctx, cl);
		break;
	case T_CL_STREAM_RECV_BODY:
		ret = process_req_body(ctx, cl);
		break;
	case T_CL_STREAM_ROUTE_BODY:
		ret = route_body(ctx, cl);
		break;
	default:
		/*
		 * TODO(ammarfaizi2): Handle T_CL_STREAM_ERROR.
		 */
		printf("Err: %s\n", cl->streams[cl->cur_stream].err_str);
		printf("Invalid state: %u\n", state);
		abort();
	}

	return ret;
}

__hot
int gwhf_consume_client_recv_buf(struct gwhf *ctx, struct gwhf_client *cl)
{
	uint8_t state = cl->streams[cl->cur_stream].state;

	assert(state != T_CL_STREAM_OFF);
	assert(state != T_CL_STREAM_SEND_HEADER);
	assert(state != T_CL_STREAM_SEND_BODY);
	(void)state;

	return consume_stream_buf(ctx, cl);
}

int gwhf_get_send_buffer(struct gwhf_client *cl, const void **buf_p,
			 size_t *len_p)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_stream_res_buf *res_buf = &stream->res_buf;

	if (res_buf->buf_len == res_buf->off) {
		/*
		 * TODO(ammarfaizi2): Handle remaining response body.
		 */
		*buf_p = NULL;
		*len_p = 0;

		if (cl->keep_alive) {
			gwhf_soft_reset_client_stream(stream);
			return 0;
		}

		return -ECONNABORTED;
	}

	*buf_p = res_buf->buf + res_buf->off;
	*len_p = res_buf->buf_len - res_buf->off;
	return 0;
}

void gwhf_advance_send_buffer(struct gwhf_client *cl, size_t len)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_stream_res_buf *res_buf = &stream->res_buf;

	assert(len <= res_buf->buf_len - res_buf->off);
	res_buf->off += len;
}
