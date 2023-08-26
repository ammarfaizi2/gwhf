// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./response.h"

#include <string.h>
#include <stdlib.h>
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

int gwhf_http_res_init(struct gwhf_http_res *res)
{
	memset(res, 0, sizeof(*res));
	return 0;
}

static void destroy_http_res_hdr(struct gwhf_http_res_hdr *hdr)
{
	struct gwhf_http_hdr_field_str *hdr_fields = hdr->hdr_fields;
	uint16_t i;

	if (!hdr_fields)
		return;

	for (i = 0; i < hdr->nr_hdr_fields; i++) {
		free(hdr_fields[i].key);
		free(hdr_fields[i].val);
	}

	free(hdr_fields);
	memset(hdr, 0, sizeof(*hdr));
}

static void destroy_http_res_body(struct gwhf_http_res_body *body)
{
	switch (body->type) {
	case GWHF_HTTP_RES_BODY_NONE:
		break;
	case GWHF_HTTP_RES_BODY_BUF:
		free(body->buf.buf);
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		break;
	case GWHF_HTTP_RES_BODY_CALLBACK:
		if (body->callback.cb_free)
			body->callback.cb_free(body->callback.arg);
		break;
#ifndef _WIN32
	case GWHF_HTTP_RES_BODY_FD:
		close(body->fd.fd);
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		break;
#endif
	default:
		abort();
		break;
	}

	memset(body, 0, sizeof(*body));
	body->type = GWHF_HTTP_RES_BODY_NONE;
}

void gwhf_http_res_destroy(struct gwhf_http_res *res)
{
	destroy_http_res_hdr(&res->hdr);
	destroy_http_res_body(&res->body);
}

static int realloc_add_one_hdr_fields(struct gwhf_http_res *res)
{
	struct gwhf_http_hdr_field_str *new_hdr_fields;
	size_t new_alloc;
	size_t new_len;

	new_len = res->hdr.nr_hdr_fields + 1;
	new_alloc = new_len * sizeof(*new_hdr_fields);
	new_hdr_fields = realloc(res->hdr.hdr_fields, new_alloc);
	if (unlikely(!new_hdr_fields))
		return -ENOMEM;

	res->hdr.hdr_fields = new_hdr_fields;
	res->hdr.nr_hdr_fields = new_len;
	return 0;
}

int gwhf_http_res_add_hdr(struct gwhf_http_res *res, const char *key,
			  const char *vfmt, ...)
{
	char *kkey, *vval;
	va_list ap;
	size_t add;
	int ret;

	add = strlen(key);
	kkey = malloc(add + 1);
	if (unlikely(!kkey))
		return -ENOMEM;

	memcpy(kkey, key, add);
	va_start(ap, vfmt);
	ret = gwhf_vasprintf(&vval, vfmt, ap);
	va_end(ap);
	if (unlikely(ret < 0)) {
		free(kkey);
		return ret;
	}

	add += (size_t)ret + sizeof(": \r\n") - 1;
	ret = realloc_add_one_hdr_fields(res);
	if (unlikely(ret < 0)) {
		free(kkey);
		free(vval);
		return ret;
	}

	res->hdr.hdr_fields[res->hdr.nr_hdr_fields - 1].key = kkey;
	res->hdr.hdr_fields[res->hdr.nr_hdr_fields - 1].val = vval;
	res->hdr.total_required_len += add;
	return 0;
}

static void del_hdr_fields_by_idx(struct gwhf_http_res *res, uint16_t idx)
{
	struct gwhf_http_hdr_field_str *hdr_fields = res->hdr.hdr_fields;
	uint16_t nr_fields = res->hdr.nr_hdr_fields;
	size_t copy_len;

	free(hdr_fields[idx].key);
	free(hdr_fields[idx].val);
	copy_len = sizeof(*hdr_fields) * (nr_fields - idx - 1);
	if (copy_len)
		memmove(&hdr_fields[idx], &hdr_fields[idx + 1], copy_len);

	res->hdr.nr_hdr_fields--;
}

int gwhf_http_res_del_hdr(struct gwhf_http_res *res, const char *key)
{
	struct gwhf_http_hdr_field_str *hdr_fields = res->hdr.hdr_fields;
	bool found = false;
	uint16_t i;

	if (!hdr_fields)
		return -ENOENT;

	for (i = 0; i < res->hdr.nr_hdr_fields; i++) {
		if (!gwhf_strcmpi(hdr_fields[i].key, key)) {
			free(hdr_fields[i].key);
			free(hdr_fields[i].val);
			del_hdr_fields_by_idx(res, i);
			found = true;
		}
	}

	if (!found)
		return -ENOENT;

	return 0;
}

char *gwhf_http_res_get_hdr(struct gwhf_http_res *res, const char *key)
{
	struct gwhf_http_hdr_field_str *hdr_fields = res->hdr.hdr_fields;
	uint16_t i;

	if (!hdr_fields)
		return NULL;

	for (i = 0; i < res->hdr.nr_hdr_fields; i++) {
		if (!gwhf_strcmpi(hdr_fields[i].key, key))
			return hdr_fields[i].val;
	}

	return NULL;
}

int gwhf_http_res_add_body_buf(struct gwhf_http_res *res, const void *buf,
			       uint64_t len)
{
	char *new_buf;
	size_t new_alloc;

	if (res->body.type == GWHF_HTTP_RES_BODY_NONE) {
		new_buf = malloc(len);
		if (unlikely(!new_buf))
			return -ENOMEM;

		memcpy(new_buf, buf, len);
		res->body.buf.buf = new_buf;
		res->body.buf.len = len;
		return 0;
	} else {
		if (res->body.type != GWHF_HTTP_RES_BODY_BUF)
			return -EINVAL;

		new_alloc = res->body.buf.len + len;
		new_buf = realloc(res->body.buf.buf, new_alloc);
		if (unlikely(!new_buf))
			return -ENOMEM;

		memcpy(new_buf + res->body.buf.len, buf, len);
		res->body.buf.buf = new_buf;
		res->body.buf.len = new_alloc;
		return 0;
	}
}

int gwhf_http_res_set_body_buf_ref(struct gwhf_http_res *res, const void *buf,
				   uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EINVAL;

	res->body.buf.buf = (char *)buf;
	res->body.buf.len = len;
	res->body.type = GWHF_HTTP_RES_BODY_BUF_REF;
	return 0;
}

int gwhf_http_res_set_body_fd(struct gwhf_http_res *res, int fd, uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EINVAL;

	res->body.fd.fd = fd;
	res->body.fd.len = len;
	res->body.type = GWHF_HTTP_RES_BODY_FD;
	return 0;
}

int gwhf_http_res_set_body_fd_ref(struct gwhf_http_res *res, int fd,
				  uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EINVAL;

	res->body.fd.fd = fd;
	res->body.fd.len = len;
	res->body.type = GWHF_HTTP_RES_BODY_FD_REF;
	return 0;
}

static inline bool has_res_headers(struct gwhf_http_res *res)
{
	return (res->hdr.total_required_len > 0);
}

static inline bool has_res_body(struct gwhf_http_res *res)
{
	return (res->body.type != GWHF_HTTP_RES_BODY_NONE);
}

static int calc_res_hdr_len(struct gwhf_http_res_hdr *hdr, const char *status)
{
	size_t len = 0;

	len += sizeof("HTTP/1.1 ") - 1;
	len += 3; /* status code */
	len += 1; /* space */
	len += status ? strlen(status) : 0;
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
	case GWHF_HTTP_RES_BODY_FD_REF:
	case GWHF_HTTP_RES_BODY_FD:
		len = body->fd.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
	case GWHF_HTTP_RES_BODY_BUF:
		len = body->buf.len;
		break;
	default:
		abort();
	}

	if (max_len && len > max_len)
		len = max_len;

	return len;
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
	case GWHF_HTTP_RES_BODY_FD_REF:
	case GWHF_HTTP_RES_BODY_FD:
		blen = body->fd.len;
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
	case GWHF_HTTP_RES_BODY_BUF:
		blen = body->buf.len;
		break;
	default:
		abort();
	}

	if (len > blen)
		len = (size_t)blen;

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_FD_REF:
	case GWHF_HTTP_RES_BODY_FD:
		ret = pread64(body->fd.fd, buf, len, off);
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
	case GWHF_HTTP_RES_BODY_BUF:
		memcpy(buf, body->buf.buf + off, len);
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

static int prepare_res_buffer(struct gwhf_http_res *res, char **buf_p,
			      size_t *len_p, const char *status)
{
	size_t len = 0;

	len += calc_res_hdr_len(&res->hdr, status);
	len += calc_res_body_len_max(&res->body, 8192);
	*buf_p = malloc(len);
	if (unlikely(!*buf_p))
		return -ENOMEM;

	*len_p = len;
	return 0;
}

static int construct_header(struct gwhf_http_res *res, char *buf, size_t alloc,
			    size_t *wr_len, const char *status)
{
	struct gwhf_http_res_hdr *hdr = &res->hdr;
	size_t len = 0;
	uint16_t i;

	len += snprintf(buf,
			alloc,
			"HTTP/1.1 %d%c%s\r\n",
			hdr->status_code,
			status ? ' ' : '\0',
			status ? status : "");

	for (i = 0; i < hdr->nr_hdr_fields; i++) {
		len += snprintf(buf + len,
				alloc - len,
				"%s: %s\r\n",
				hdr->hdr_fields[i].key,
				hdr->hdr_fields[i].val);
	}

	buf[len++] = '\r';
	buf[len++] = '\n';
	*wr_len = len;
	return 0;
}

static int construct_body(struct gwhf_http_res *res, char *buf, size_t alloc,
			  size_t *wr_len)
{
	size_t len = *wr_len;
	size_t avail = alloc - len;
	int ret;

	ret = copy_res_body(&res->body, buf + len, avail);
	if (unlikely(ret < 0))
		return ret;

	len += (size_t)ret;
	*wr_len = len;
	return 0;
}

int gwhf_http_res_construct_first_res(struct gwhf_http_res *res, char **buf_p,
				      size_t *len_p)
{
	const char *status;
	size_t wr_len = 0;
	int ret;

	if (!has_res_headers(res) && !has_res_body(res)) {
		gwhf_http_res_set_status_code(res, 204);
		ret = gwhf_http_res_add_hdr(res, "Content-Length", "0");
		if (unlikely(ret))
			return ret;
	}

	status = gwhf_http_code_to_str(res->hdr.status_code);
	ret = prepare_res_buffer(res, buf_p, len_p, status);
	if (unlikely(ret))
		return ret;

	ret = construct_header(res, *buf_p, *len_p, &wr_len, status);
	if (unlikely(ret))
		return ret;

	ret = construct_body(res, *buf_p, *len_p, &wr_len);
	if (unlikely(ret))
		return ret;

	(void)wr_len;
	return 0;
}
