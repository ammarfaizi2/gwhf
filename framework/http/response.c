// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
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
	char *kkey;
	char *vval;
	int err;

	kkey = strdup(key);
	if (unlikely(!kkey))
		return -ENOMEM;

	va_start(ap, vfmt);
	err = vasprintf(&vval, vfmt, ap);
	va_end(ap);
	if (unlikely(err < 0)) {
		free(kkey);
		return -ENOMEM;
	}

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
	hdr->total_len_req += err + strlen(kkey) + sizeof(": \r\n") - 1;

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

static uint64_t compute_res_body_len_max(struct gwhf_http_res_body *body,
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

struct construct_info {
	char		*res_buf;
	size_t		res_buf_alloc;
	uint32_t	preconsumed_body_len;
};

static int prepare_res_buffer(struct gwhf_client *cl, struct construct_info *ci,
			      const char *hcode_str)
{
	struct gwhf_client_stream *stream = &cl->streams[0];
	size_t size_needed = 0;
	uint64_t blen;
	char *res_buf;

	size_needed += (size_t)snprintf(NULL, 0, "HTTP/1.1 %d %s\r\n",
					stream->res_hdr.status, hcode_str);

	size_needed += stream->res_hdr.total_len_req;
	size_needed += sizeof("\r\n") - 1;

	blen = compute_res_body_len_max(&cl->streams[0].res_body, 8192);
	ci->preconsumed_body_len = (uint32_t)blen;
	size_needed += blen;

	if (size_needed > ci->res_buf_alloc) {
		res_buf = realloc(ci->res_buf, size_needed);
		if (unlikely(!res_buf))
			return -ENOMEM;

		ci->res_buf = res_buf;
		ci->res_buf_alloc = size_needed;
	}

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

static int __gwhf_construct_response(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[0];
	struct construct_info ci = {
		.preconsumed_body_len = 0,
		.res_buf = cl->streams[0].res_buf,
		.res_buf_alloc = cl->streams[0].res_buf_alloc,
	};
	const char *hcode_str;
	size_t alloc_len, len;
	char *res_buf;
	ssize_t cpret;
	uint16_t i;
	int err;

	assert(!stream->res_buf_len);

	hcode_str = gwhf_http_code_to_str(stream->res_hdr.status);
	if (!hcode_str)
		hcode_str = "Unknown";

	err = prepare_res_buffer(cl, &ci, hcode_str);
	if (unlikely(err))
		return err;

	stream->res_buf_len = 0;
	stream->res_buf = res_buf = ci.res_buf;
	stream->res_buf_alloc = alloc_len = ci.res_buf_alloc;

	len = (size_t)snprintf(res_buf, alloc_len, "HTTP/1.1 %d %s\r\n",
			       stream->res_hdr.status, hcode_str);

	for (i = 0; i < stream->res_hdr.nr_hdr_fields; i++) {
		len += (size_t)snprintf(res_buf + len, alloc_len - len,
					"%s: %s\r\n",
					stream->res_hdr.hdr_fields[i].key,
					stream->res_hdr.hdr_fields[i].val);
	}

	res_buf[len++] = '\r';
	res_buf[len++] = '\n';
	cpret = copy_res_body(&stream->res_body, res_buf + len,
			      alloc_len - len);
	if (unlikely(cpret < 0)) {
		stream->res_buf_len = 0;
		return (int)cpret;
	}

	stream->res_buf_len = len + (size_t)cpret;
	return 0;
}

int gwhf_construct_response(struct gwhf_client *cl)
{
	int ret = __gwhf_construct_response(cl);

	gwhf_destroy_http_res_hdr(&cl->streams[0].res_hdr);
	return ret;
}

int gwhf_init_res_buf(struct gwhf_client_stream *stream)
{
	uint32_t alloc = 8192u;
	char *buf;

	assert(!stream->res_buf);
	assert(!stream->res_buf_len);
	assert(!stream->res_buf_alloc);
	assert(!stream->res_buf_sent);

	buf = malloc(alloc);
	if (unlikely(!buf))
		return -ENOMEM;

	stream->res_buf = buf;
	stream->res_buf_len = 0u;
	stream->res_buf_alloc = alloc;
	stream->res_buf_sent = 0u;
	return 0;
}

void gwhf_destroy_res_buf(struct gwhf_client_stream *stream)
{
	free(stream->res_buf);
	stream->res_buf = NULL;
	stream->res_buf_len = 0u;
	stream->res_buf_alloc = 0u;
	stream->res_buf_sent = 0u;
	stream->res_buf_done = false;
}

int gwhf_init_http_res_hdr(struct gwhf_http_res_hdr *hdr)
{
	return 0;
}

int gwhf_init_http_res_body(struct gwhf_http_res_body *body)
{
	return 0;
}

void gwhf_destroy_http_res_hdr(struct gwhf_http_res_hdr *hdr)
{
	uint16_t i;

	for (i = 0; i < hdr->nr_hdr_fields; i++) {
		free(hdr->hdr_fields[i].key);
		free(hdr->hdr_fields[i].val);
	}

	free(hdr->hdr_fields);
	memset(hdr, 0, sizeof(*hdr));
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
	struct gwhf_client_stream *stream = &cl->streams[0];

	stream->res_hdr.status = http_code;
	return 0;
}
