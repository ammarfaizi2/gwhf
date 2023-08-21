// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#include "response.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

const char *gwhf_http_code_to_str(int http_code)
{
	switch (http_code) {
	case 100:
		return "Continue";
	case 101:
		return "Switching Protocols";
	case 200:
		return "OK";
	case 201:
		return "Created";
	case 202:
		return "Accepted";
	case 204:
		return "No Content";
	case 206:
		return "Partial Content";
	case 300:
		return "Multiple Choices";
	case 301:
		return "Moved Permanently";
	case 302:
		return "Found";
	case 303:
		return "See Other";
	case 304:
		return "Not Modified";
	case 307:
		return "Temporary Redirect";
	case 308:
		return "Permanent Redirect";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 405:
		return "Method Not Allowed";
	case 406:
		return "Not Acceptable";
	case 408:
		return "Request Timeout";
	case 409:
		return "Conflict";
	case 410:
		return "Gone";
	case 411:
		return "Length Required";
	case 413:
		return "Payload Too Large";
	case 414:
		return "URI Too Long";
	case 415:
		return "Unsupported Media Type";
	case 416:
		return "Range Not Satisfiable";
	case 417:
		return "Expectation Failed";
	case 422:
		return "Unprocessable Entity";
	case 429:
		return "Too Many Requests";
	case 500:
		return "Internal Server Error";
	case 501:
		return "Not Implemented";
	case 502:
		return "Bad Gateway";
	case 503:
		return "Service Unavailable";
	case 504:
		return "Gateway Timeout";
	case 505:
		return "HTTP Version Not Supported";
	default:
		return NULL;
	}
}

int gwhf_add_http_res_hdr(struct gwhf_client *cl, const char *key,
			  const char *vfmt, ...)
{
	struct gwhf_http_res_hdr *hdr = &cl->streams[0].res_hdr;
	struct gwhf_http_hdr_field_str *tmp, *hdr_fields = hdr->hdr_fields;
	uint16_t nr_hdr_fields = hdr->nr_hdr_fields;
	va_list ap;
	size_t key_len;
	size_t val_len;
	char *kkey;
	char *vval;
	int ret;

	key_len = strlen(key);
	kkey = malloc(key_len + 1u);
	if (unlikely(!kkey))
		return -ENOMEM;

	memcpy(kkey, key, key_len + 1u);

	va_start(ap, vfmt);
	ret = vasprintf(&vval, vfmt, ap);
	va_end(ap);
	if (unlikely(ret < 0)) {
		free(kkey);
		return -ENOMEM;
	}

	val_len = (size_t)ret;

	tmp = realloc(hdr_fields, sizeof(*hdr_fields) * (nr_hdr_fields + 1));
	if (unlikely(!tmp)) {
		free(kkey);
		free(vval);
		return -ENOMEM;
	}

	hdr_fields = tmp;
	hdr_fields[nr_hdr_fields].key = kkey;
	hdr_fields[nr_hdr_fields].val = vval;
	hdr->hdr_fields = hdr_fields;
	hdr->nr_hdr_fields = nr_hdr_fields + 1;
	hdr->total_required_len += key_len + val_len + sizeof(": \r\n") - 1;

	return 0;
}

int gwhf_add_http_res_body_buf(struct gwhf_client *cl, const void *buf,
			       uint64_t len)
{
	struct gwhf_http_res_body *body = &cl->streams[0].res_body;
	uint8_t *tmp;

	if (unlikely(body->type != GWHF_HTTP_RES_BODY_BUF &&
		     body->type != GWHF_HTTP_RES_BODY_NONE))
		return -EBUSY;

	tmp = realloc(body->buf.buf, body->buf.len + len);
	if (unlikely(!tmp))
		return -ENOMEM;

	memcpy(tmp + body->buf.len, buf, len);
	body->buf.buf = tmp;
	body->buf.len += len;
	body->type = GWHF_HTTP_RES_BODY_BUF;

	return 0;
}

int gwhf_set_http_res_body_buf_ref(struct gwhf_client *cl, const void *buf,
				   uint64_t len)
{
	struct gwhf_http_res_body *body = &cl->streams[0].res_body;

	if (unlikely(body->type != GWHF_HTTP_RES_BODY_BUF_REF &&
		     body->type != GWHF_HTTP_RES_BODY_NONE))
		return -EBUSY;

	body->buf_ref.buf = (void *)buf;
	body->buf_ref.len = len;
	body->type = GWHF_HTTP_RES_BODY_BUF_REF;

	return 0;
}

static int __gwhf_set_http_res_body_fd(struct gwhf_client *cl, int fd,
				       uint64_t len, bool take_ownership)
{
	struct gwhf_http_res_body *body = &cl->streams[0].res_body;

	if (unlikely(body->type != GWHF_HTTP_RES_BODY_FD &&
		     body->type != GWHF_HTTP_RES_BODY_NONE))
		return -EBUSY;

	body->fd.fd = fd;
	body->fd.len = len;

	if (take_ownership)
		body->type = GWHF_HTTP_RES_BODY_FD;
	else
		body->type = GWHF_HTTP_RES_BODY_FD_REF;

	return 0;
}

int gwhf_set_http_res_body_fd(struct gwhf_client *cl, int fd, uint64_t len)
{
	return __gwhf_set_http_res_body_fd(cl, fd, len, true);
}

int gwhf_set_http_res_body_fd_ref(struct gwhf_client *cl, int fd, uint64_t len)
{
	return __gwhf_set_http_res_body_fd(cl, fd, len, false);
}

static int calc_res_hdr_len(struct gwhf_http_res_hdr *hdr)
{
	size_t len = 0;

	len += sizeof("HTTP/1.1 ") - 1;
	len += 3; /* status code */
	len += 1; /* space */
	len += strlen(gwhf_http_code_to_str(hdr->status));
	len += sizeof("\r\n") - 1;      /* first CRLF */
	len += hdr->total_required_len; /* header fields */
	len += sizeof("\r\n") - 1;      /* last CRLF */
	return (int)len;
}

static uint64_t calc_res_body_len_max(struct gwhf_http_res_body *body,
				      uint64_t max_len)
{
	uint64_t len;

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_NONE:
		len = 0;
		break;
	case GWHF_HTTP_RES_BODY_FD:
		len = body->fd.len;
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		len = body->fd_ref.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF:
		len = body->buf.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		len = body->buf_ref.len;
		break;
	default:
		abort();
	}

	if (max_len && len > max_len)
		len = max_len;

	return len;
}

static int prepare_res_buffer(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_stream_res_buf *res_buf = &stream->res_buf;
	size_t total = 0;

	total += calc_res_hdr_len(&stream->res_hdr);
	total += calc_res_body_len_max(&stream->res_body, 8192);

	if (total > res_buf->buf_alloc) {
		char *tmp;

		tmp = realloc(res_buf->buf, total);
		if (unlikely(!tmp))
			return -ENOMEM;

		res_buf->buf = tmp;
		res_buf->buf_alloc = total;
	}

	return 0;
}

static int construct_header(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_stream_res_buf *res_buf = &stream->res_buf;
	struct gwhf_http_res_hdr *hdr = &stream->res_hdr;
	size_t avail = res_buf->buf_alloc;
	char *buf = res_buf->buf;
	size_t len = 0;
	uint16_t i;

	assert(avail >= hdr->total_required_len);
	assert(!res_buf->buf_len);

	len += snprintf(buf + len, avail - len, "HTTP/1.1 %d %s\r\n",
			hdr->status, gwhf_http_code_to_str(hdr->status));

	for (i = 0; i < hdr->nr_hdr_fields; i++) {
		len += snprintf(buf + len, avail - len, "%s: %s\r\n",
				hdr->hdr_fields[i].key,
				hdr->hdr_fields[i].val);
	}

	buf[len++] = '\r';
	buf[len++] = '\n';
	res_buf->buf_len = len;
	return 0;
}

static ssize_t copy_res_body(struct gwhf_http_res_body *body, void *buf,
			     size_t len)
{
	uint64_t off = body->off;
	ssize_t ret = 0;
	uint64_t blen;

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_NONE:
		return 0;
	case GWHF_HTTP_RES_BODY_FD:
		blen = body->fd.len;
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		blen = body->fd_ref.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF:
		blen = body->buf.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		blen = body->buf_ref.len;
		break;
	default:
		abort();
	}

	if (len > blen)
		len = (size_t)blen;

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_FD:
		ret = pread64(body->fd.fd, buf, len, off);
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		ret = pread64(body->fd_ref.fd, buf, len, off);
		break;
	case GWHF_HTTP_RES_BODY_BUF:
		memcpy(buf, body->buf.buf + off, len);
		ret = (ssize_t)len;
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		memcpy(buf, body->buf_ref.buf + off, len);
		ret = (ssize_t)len;
		break;
	case GWHF_HTTP_RES_BODY_NONE:
	default:
		abort();
	}

	if (ret > 0)
		body->off += (uint64_t)ret;

	return ret;
}

static int construct_body(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_stream_res_buf *res_buf = &stream->res_buf;
	size_t avail = res_buf->buf_alloc - res_buf->buf_len;
	char *buf = res_buf->buf + res_buf->buf_len;
	int ret;

	ret = copy_res_body(&stream->res_body, buf, avail);
	if (unlikely(ret < 0))
		return ret;

	res_buf->buf_len += (size_t)ret;
	return 0;
}

static bool has_res_headers(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_http_res_hdr *hdr = &stream->res_hdr;

	return (hdr->total_required_len != 0);
}

static bool has_res_body(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	struct gwhf_http_res_body *body = &stream->res_body;

	return (body->type != GWHF_HTTP_RES_BODY_NONE);
}

static bool should_be_kept_alive(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	const char *tmp;

	tmp = gwhf_get_http_req_hdr(&stream->req_hdr, "connection");
	if (tmp && !strcasecmp(tmp, "keep-alive"))
		return true;

	tmp = gwhf_get_http_req_version(&stream->req_hdr);
	if (!strcmp(tmp, "HTTP/1.1"))
		return true;

	return false;
}

static int append_keep_alive_if_needed(struct gwhf_client *cl)
{
	if (should_be_kept_alive(cl)) {
		cl->keep_alive = true;
		return gwhf_add_http_res_hdr(cl, "Connection", "keep-alive");
	} else {
		cl->keep_alive = false;
		return gwhf_add_http_res_hdr(cl, "Connection", "close");
	}
}

int gwhf_construct_response(struct gwhf_client *cl)
{
	int ret;

	if (!has_res_headers(cl) && !has_res_body(cl)) {
		gwhf_set_http_res_code(cl, 204);
		ret = gwhf_add_http_res_hdr(cl, "Content-Length", "0");
		if (unlikely(ret))
			return ret;
	}

	ret = append_keep_alive_if_needed(cl);
	if (unlikely(ret))
		return ret;

	ret = prepare_res_buffer(cl);
	if (unlikely(ret))
		return ret;

	ret = construct_header(cl);
	if (unlikely(ret))
		return ret;

	ret = construct_body(cl);
	if (unlikely(ret))
		return ret;

	return 0;
}

int gwhf_init_http_res_hdr(struct gwhf_http_res_hdr *hdr)
{
	assert(!hdr->hdr_fields);
	assert(!hdr->nr_hdr_fields);
	assert(!hdr->status);
	assert(!hdr->total_required_len);
	return 0;
}

void gwhf_destroy_http_res_hdr(struct gwhf_http_res_hdr *hdr)
{
	uint16_t i;

	if (hdr->hdr_fields) {
		assert(hdr->total_required_len);

		for (i = 0; i < hdr->nr_hdr_fields; i++) {
			free(hdr->hdr_fields[i].key);
			free(hdr->hdr_fields[i].val);
		}

		free(hdr->hdr_fields);
	} else {
		assert(!hdr->nr_hdr_fields);
		assert(!hdr->total_required_len);
	}

	memset(hdr, 0, sizeof(*hdr));
}

int gwhf_init_http_res_body(struct gwhf_http_res_body *body)
{
	assert(!body->type);
	assert(!body->off);
	assert(!body->callback_done);
	assert(!body->cb_arg);
	return 0;
}

void gwhf_destroy_http_res_body(struct gwhf_http_res_body *body)
{
	switch (body->type) {
	case GWHF_HTTP_RES_BODY_NONE:
	case GWHF_HTTP_RES_BODY_BUF:
		free(body->buf.buf);
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		break;
	case GWHF_HTTP_RES_BODY_FD:
		close(body->fd.fd);
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		break;
	default:
		abort();
	}

	if (body->callback_done)
		body->callback_done(body->cb_arg);

	memset(body, 0, sizeof(*body));
}

int gwhf_set_http_res_code(struct gwhf_client *cl, int http_code)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];

	if (http_code < 100 || http_code > 599)
		return -EINVAL;

	stream->res_hdr.status = http_code;
	return 0;
}

int gwhf_init_res_buf(struct gwhf_stream_res_buf *res_buf)
{
	assert(!res_buf->buf);
	assert(!res_buf->buf_len);
	assert(!res_buf->buf_alloc);
	assert(!res_buf->off);
	(void)res_buf;
	return 0;
}

void gwhf_destroy_res_buf(struct gwhf_stream_res_buf *res_buf)
{
	if (res_buf->buf) {
		assert(res_buf->buf_alloc);
		free(res_buf->buf);
		memset(res_buf, 0, sizeof(*res_buf));
	} else {
		assert(!res_buf->buf_len);
		assert(!res_buf->buf_alloc);
		assert(!res_buf->off);
	}
}
