// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#if defined(__linux__)
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "response.h"

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

int gwhf_http_res_set_body_buf_ref(struct gwhf_http_res *res, const void *buf,
				   uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EBUSY;

	res->body.type = GWHF_HTTP_RES_BODY_BUF_REF;
	res->body.buf.buf = (void *)buf;
	res->body.buf.len = len;
	return 0;
}

int gwhf_http_res_add_body_buf(struct gwhf_http_res *res, const void *buf,
			       uint64_t len)
{
	size_t new_len;
	char *new_buf;

	if (res->body.type != GWHF_HTTP_RES_BODY_NONE &&
	    res->body.type != GWHF_HTTP_RES_BODY_BUF)
		return -EBUSY;

	new_len = res->body.buf.len + len;
	new_buf = realloc(res->body.buf.buf, new_len);
	if (unlikely(!new_buf))
		return -ENOMEM;

	memcpy(new_buf + res->body.buf.len, buf, len);
	res->body.buf.buf = new_buf;
	res->body.buf.len = new_len;
	res->body.type = GWHF_HTTP_RES_BODY_BUF;
	return 0;
}

#if !defined(_WIN32)
int gwhf_http_res_set_body_fd(struct gwhf_http_res *res, int fd, uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EBUSY;

	res->body.type = GWHF_HTTP_RES_BODY_FD;
	res->body.fd.fd = fd;
	res->body.fd.len = len;
	return 0;
}

int gwhf_http_res_set_body_fd_ref(struct gwhf_http_res *res, int fd,
				  uint64_t len)
{
	if (res->body.type != GWHF_HTTP_RES_BODY_NONE)
		return -EBUSY;

	res->body.type = GWHF_HTTP_RES_BODY_FD_REF;
	res->body.fd.fd = fd;
	res->body.fd.len = len;
	return 0;
}
#endif /* #if !defined(_WIN32) */

int gwhf_http_res_del_hdr(struct gwhf_http_res *res, const char *key)
{
	struct gwhf_http_hdr_field_str *fields = res->hdr.hdr_fields;
	uint16_t i, nr_fields = res->hdr.nr_hdr_fields;
	bool found = false;

	for (i = 0; i < nr_fields; ++i) {
		size_t subt_len = 0;
		size_t move_len;

		if (gwhf_strcmpi(fields[i].key, key))
			continue;

		subt_len += strlen(fields[i].key);
		subt_len += strlen(fields[i].val);
		subt_len += sizeof(": \r\n") - 1;
		res->hdr.total_requried_len -= subt_len;

		free(fields[i].key);
		free(fields[i].val);
		found = true;

		--nr_fields;
		if (nr_fields == i)
			break;

		move_len = sizeof(*fields) * (nr_fields - i);
		memmove(fields + i, fields + i + 1, move_len);
		--i;
	}

	if (found) {
		if (!nr_fields) {
			free(fields);
			res->hdr.hdr_fields = NULL;
		}
		res->hdr.nr_hdr_fields = nr_fields;
		return 0;
	}

	return -ENOENT;
}

int gwhf_http_res_add_hdr(struct gwhf_http_res *res, const char *akey,
			  const char *vfmt, ...)
{
	struct gwhf_http_hdr_field_str *tmp, *fields = res->hdr.hdr_fields;
	uint16_t new_nr_hdr_fields = res->hdr.nr_hdr_fields + 1;
	char *key = NULL, *val = NULL;
	size_t key_len;
	size_t val_len;
	size_t len;
	va_list ap;

	key_len = strlen(akey);
	key = malloc(key_len + 1);
	if (unlikely(!key))
		return -ENOMEM;

	memcpy(key, akey, key_len + 1);

	va_start(ap, vfmt);

	len = (size_t)snprintf(NULL, 0, vfmt, ap);
	if (unlikely((res->hdr.total_requried_len + len + key_len) >= UINT16_MAX))
		goto out_va_end;

	val = malloc(len);
	if (unlikely(!val))
		goto out_va_end;

	val_len = snprintf(val, len, vfmt, ap);
	va_end(ap);

	tmp = realloc(fields, sizeof(*fields) * new_nr_hdr_fields);
	if (unlikely(!tmp))
		goto out_free_val;

	fields = tmp;
	fields[new_nr_hdr_fields - 1].key = key;
	fields[new_nr_hdr_fields - 1].val = val;
	res->hdr.hdr_fields = fields;
	res->hdr.nr_hdr_fields = new_nr_hdr_fields;
	res->hdr.total_requried_len += key_len + val_len + sizeof(": \r\n") - 1;
	return 0;

out_va_end:
	va_end(ap);
out_free_val:
	free(val);
	free(key);
	return -ENOMEM;
}

char *gwhf_http_res_get_hdr(struct gwhf_http_res *res, const char *key)
{
	struct gwhf_http_hdr_field_str *fields = res->hdr.hdr_fields;
	uint16_t i, nr_fields = res->hdr.nr_hdr_fields;

	for (i = 0; i < nr_fields; ++i) {
		if (gwhf_strcmpi(fields[i].key, key))
			continue;

		return fields[i].val;
	}

	return NULL;
}

int gwhf_http_res_init(struct gwhf_http_res *res)
{
	assert(res->hdr.status_code == 0);
	return 0;
}

static void gwhf_http_res_hdr_destroy(struct gwhf_http_res_hdr *hdr)
{
	if (hdr->hdr_fields)
		free(hdr->hdr_fields);

	memset(hdr, 0, sizeof(*hdr));
}

static void gwhf_http_res_body_destroy(struct gwhf_http_res_body *body)
{
	switch (body->type) {
	case GWHF_HTTP_RES_BODY_BUF:
		if (body->buf.buf)
			free(body->buf.buf);
		break;
	case GWHF_HTTP_RES_BODY_BUF_REF:
		break;
	case GWHF_HTTP_RES_BODY_FD:
#if defined(__linux__)
		close(body->fd.fd);
#endif
		break;
	case GWHF_HTTP_RES_BODY_FD_REF:
		break;
	case GWHF_HTTP_RES_BODY_CALLBACK:
		if (body->callback.cb_free)
			body->callback.cb_free(body->callback.arg);
		break;
	}

	memset(body, 0, sizeof(*body));
}

void gwhf_http_res_destroy(struct gwhf_http_res *res)
{
	gwhf_http_res_hdr_destroy(&res->hdr);
	gwhf_http_res_body_destroy(&res->body);
}

static size_t calc_res_body_max(struct gwhf_http_res *res, size_t max)
{
	size_t len;

	switch (res->body.type) {
	case GWHF_HTTP_RES_BODY_BUF:
	case GWHF_HTTP_RES_BODY_BUF_REF:
		len = res->body.buf.len - res->body.off;
		break;
	case GWHF_HTTP_RES_BODY_FD:
	case GWHF_HTTP_RES_BODY_FD_REF:
		len = res->body.fd.len - res->body.off;
		break;
	case GWHF_HTTP_RES_BODY_NONE:
	case GWHF_HTTP_RES_BODY_CALLBACK:
	default:
		return 0;
	}

	if (len > max)
		len = max;

	return len;
}

static int prepare_buffer(struct gwhf_http_res *res, const char *http_code,
			  char **buf_p, uint32_t *len_p)
{
	uint32_t len = 0;
	char *buf;

	len += sizeof("HTTP/1.1 xxx ") - 1;
	len += strlen(http_code);
	len += sizeof("\r\n") - 1;
	len += res->hdr.total_requried_len;
	len += sizeof("\r\n") - 1;
	len += calc_res_body_max(res, 8192);
	buf = malloc(len + 1u);
	if (unlikely(!buf))
		return -ENOMEM;

	*buf_p = buf;
	*len_p = len;
	return 0;
}

static int copy_res_body(char *dst, struct gwhf_http_res_body *body, size_t len)
{
	size_t copy_len;
#if defined(__linux__)	
	ssize_t ret;
#endif

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_BUF:
	case GWHF_HTTP_RES_BODY_BUF_REF:
		copy_len = body->buf.len - body->off;
		break;
#if defined(__linux__)
	case GWHF_HTTP_RES_BODY_FD:
	case GWHF_HTTP_RES_BODY_FD_REF:
		copy_len = body->fd.len - body->off;
		break;
#endif
	case GWHF_HTTP_RES_BODY_NONE:
	case GWHF_HTTP_RES_BODY_CALLBACK:
	default:
		return 0;
	}

	if (copy_len > len)
		copy_len = len;

	switch (body->type) {
	case GWHF_HTTP_RES_BODY_BUF:
	case GWHF_HTTP_RES_BODY_BUF_REF:
		memcpy(dst, body->buf.buf + body->off, copy_len);
		body->off += copy_len;
		break;
#if defined(__linux__)
	case GWHF_HTTP_RES_BODY_FD:
	case GWHF_HTTP_RES_BODY_FD_REF:
		ret = pread64(body->fd.fd, dst, copy_len, body->off);
		if (unlikely(ret < 0))
			return -errno;
		body->off += (uint64_t)ret;
		break;
#endif
	}

	return (int)copy_len;
}

int gwhf_http_res_construct_first_res(struct gwhf_http_res *res, char **buf_p,
				      size_t *len_p)
{
	const char *http_code;
	uint32_t pos;
	uint32_t len;
	uint16_t i;
	char *buf;
	int ret;

	http_code = gwhf_http_code_to_str(res->hdr.status_code);
	if (!http_code) {
		res->hdr.status_code = 200;
		http_code = gwhf_http_code_to_str(200);
	}

	ret = prepare_buffer(res, http_code, &buf, &len);
	if (unlikely(ret))
		return ret;

	pos = 0;
	ret = snprintf(buf, len, "HTTP/1.1 %hd %s\r\n", res->hdr.status_code,
		       http_code);

	for (i = 0; i < res->hdr.nr_hdr_fields; ++i) {
		ret = snprintf(buf + pos, len - pos, "%s: %s\r\n",
			       res->hdr.hdr_fields[i].key,
			       res->hdr.hdr_fields[i].val);
		pos += (size_t)ret;
	}

	buf[pos++] = '\r';
	buf[pos++] = '\n';
	ret = copy_res_body(buf + pos, &res->body, len - pos);
	if (unlikely(ret)) {
		free(buf);
		return ret;
	}

	pos += (uint32_t)ret;
	buf[pos] = '\0';

	*buf_p = buf;
	*len_p = len;
	return 0;
}
