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

static const char *http_code_to_str(int code)
{
	switch (code) {
	case 200:
		return "OK";
	case 201:
		return "Created";
	case 202:
		return "Accepted";
	case 203:
		return "Non-Authoritative Information";
	case 204:
		return "No Content";
	case 205:
		return "Reset Content";
	case 206:
		return "Partial Content";
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
	case 500:
		return "Internal Server Error";
	case 501:
		return "Not Implemented";
	case 503:
		return "Service Unavailable";
	default:
		return "";
	}
}

static uint64_t compute_total_res_body_len(struct gwhf_res_body *body)
{
	switch (body->type) {
	case GWHF_RES_BODY_TYPE_NONE:
		return 0;
	case GWHF_RES_BODY_TYPE_FD:
		return body->fd.len;
	case GWHF_RES_BODY_TYPE_REF_FD:
		return body->fd.len;
	case GWHF_RES_BODY_TYPE_BUF:
		return body->buf.len;
	case GWHF_RES_BODY_TYPE_REF_BUF:
		return body->ref_buf.len;
	}

	abort();
}

static int copy_res_body_to_buf(struct gwhf_res_body *body, char *buf,
				size_t len)
{
	ssize_t ret;

	switch (body->type) {
	case GWHF_RES_BODY_TYPE_NONE:
		return 0;
	case GWHF_RES_BODY_TYPE_FD:
	case GWHF_RES_BODY_TYPE_REF_FD:
		ret = pread64(body->fd.fd, buf, len, body->off);
		if (unlikely(ret < 0))
			return -errno;
		body->off += (uint64_t)ret;
		return 0;
	case GWHF_RES_BODY_TYPE_BUF:
		memcpy(buf, body->buf.buf, len);
		body->off += (uint64_t)len;
		return 0;
	case GWHF_RES_BODY_TYPE_REF_BUF:
		memcpy(buf, body->ref_buf.buf, len);
		body->off += (uint64_t)len;
		return 0;
	}

	abort();
}

int gwhf_construct_res_buf(struct gwhf_client *cl)
{
	struct gwhf_res_body *body = &cl->res_body;
	struct gwhf_res_hdr *hdr = &cl->res_hdr;
	const char *status_str;
	size_t body_len;
	size_t hdr_len;
	size_t tot_len;
	size_t len;
	uint16_t i;
	char *buf;
	int err;

	assert(cl->res_buf_sent == 0);
	assert(cl->res_buf_len == 0);

	status_str = http_code_to_str(hdr->status_code);

	body_len = (size_t)compute_total_res_body_len(body);

	hdr_len = (size_t)hdr->total_req_len;
	hdr_len += sizeof("\r\n\r\n") - 1u;
	hdr_len += snprintf(NULL, 0, "HTTP/1.1 %hd %s\r\n", hdr->status_code,
			    status_str);

	if (unlikely(hdr_len > 65535u))
		return -ENOMEM;

	tot_len = hdr_len + body_len;
	if (tot_len > 65535u*2u) {
		tot_len = 65535u*2u;
		body_len = tot_len - hdr_len;
	}

	buf = malloc(tot_len);
	if (unlikely(!buf))
		return -ENOMEM;

	len = snprintf(buf, tot_len, "HTTP/1.1 %hd %s\r\n", hdr->status_code,
		       status_str);

	for (i = 0; i < hdr->nr_fields; i++) {
		len += snprintf(buf + len, tot_len - len, "%s: %s\r\n",
				hdr->fields[i].key, hdr->fields[i].val);
	}

	buf[len++] = '\r';
	buf[len++] = '\n';
	err = copy_res_body_to_buf(body, buf + len, body_len);
	if (unlikely(err < 0)) {
		free(buf);
		return err;
	}

	cl->res_buf = buf;
	cl->res_buf_len = len + body_len;
	cl->res_buf_sent = 0;
	return 0;
}

int gwhf_res_body_add_buf(struct gwhf_client *cl, const void *buf, uint64_t len)
{
	struct gwhf_res_body *body = &cl->res_body;
	struct gwhf_res_body_buf *body_buf = &body->buf;
	char *tmp;

	if (unlikely(len == 0))
		return -EINVAL;

	if (unlikely(body->type != GWHF_RES_BODY_TYPE_NONE &&
		     body->type != GWHF_RES_BODY_TYPE_BUF))
		return -EBUSY;

	if (body->type == GWHF_RES_BODY_TYPE_NONE) {
		tmp = memdup(buf, len);
		if (unlikely(!tmp))
			return -ENOMEM;

		body->type = GWHF_RES_BODY_TYPE_BUF;
		body_buf->buf = tmp;
		body_buf->len = len;
	} else {
		tmp = realloc(body_buf->buf, body_buf->len + len);
		if (unlikely(!tmp))
			return -ENOMEM;

		memcpy(tmp + body_buf->len, buf, len);
		body_buf->buf = tmp;
		body_buf->len += len;
	}

	return 0;
}

int gwhf_res_body_set_ref_buf(struct gwhf_client *cl, const void *buf,
			      uint64_t len)
{
	struct gwhf_res_body *body = &cl->res_body;
	struct gwhf_res_body_buf *body_buf = &body->ref_buf;

	if (unlikely(len == 0))
		return -EINVAL;

	if (unlikely(body->type != GWHF_RES_BODY_TYPE_NONE))
		return -EBUSY;

	body->type = GWHF_RES_BODY_TYPE_REF_BUF;
	body_buf->buf = (void *)buf;
	body_buf->len = len;
	return 0;
}

static int __gwhf_res_body_set_fd(struct gwhf_client *cl, int fd, uint64_t len)
{
	struct gwhf_res_body *body = &cl->res_body;

	if (unlikely(len == 0))
		return -EINVAL;

	if (unlikely(body->type != GWHF_RES_BODY_TYPE_NONE))
		return -EBUSY;

	body->fd.fd = fd;
	body->fd.len = len;
	return 0;
}

int gwhf_res_body_set_fd(struct gwhf_client *cl, int fd, uint64_t len)
{
	int ret;

	ret = __gwhf_res_body_set_fd(cl, fd, len);
	if (unlikely(ret < 0))
		return ret;

	cl->res_body.type = GWHF_RES_BODY_TYPE_FD;
	return 0;
}

int gwhf_res_body_set_ref_fd(struct gwhf_client *cl, int fd, uint64_t len)
{
	int ret;

	ret = __gwhf_res_body_set_fd(cl, fd, len);
	if (unlikely(ret < 0))
		return ret;

	cl->res_body.type = GWHF_RES_BODY_TYPE_REF_FD;
	return 0;
}

static int gwhf_res_hdr_plug_field(struct gwhf_res_hdr *hdr, char *key,
				   char *val)
{
	struct gwhf_hdr_field_str *fields = hdr->fields;
	size_t new_nr;

	new_nr = (size_t)hdr->nr_fields + 1u;
	if (new_nr > 65535u)
		return -ENOMEM;

	fields = realloc(fields, sizeof(*fields) * new_nr);
	if (unlikely(!fields))
		return -ENOMEM;

	hdr->fields = fields;
	hdr->nr_fields = (uint16_t)new_nr;
	hdr->fields[new_nr - 1].key = key;
	hdr->fields[new_nr - 1].val = val;
	return 0;
}

int gwhf_res_hdr_add_field(struct gwhf_res_hdr *hdr, const char *key,
			   const char *fmtval, ...)
{
	char *kkey, *vval;
	size_t key_len;
	size_t val_len;
	va_list ap;
	int ret;

	va_start(ap, fmtval);
	ret = vasprintf(&vval, fmtval, ap);
	va_end(ap);
	if (unlikely(ret < 0))
		return -ENOMEM;

	val_len = (size_t)ret;
	key_len = strlen(key);

	kkey = memdup(key, key_len + 1u);
	if (unlikely(!kkey)) {
		free(vval);
		return -ENOMEM;
	}

	ret = gwhf_res_hdr_plug_field(hdr, kkey, vval);
	if (unlikely(ret < 0)) {
		free(kkey);
		free(vval);
		return ret;
	}

	/*
	 * Add the length of the key, value, ": " and "\r\n".
	 */
	hdr->total_req_len += key_len + val_len + sizeof("\r\n\r\n") + sizeof(": ");
	return 0;
}

static void destroy_res_body_fd(struct gwhf_res_body_fd *fd)
{
	if (fd->fd >= 0)
		close(fd->fd);
}

static void destroy_res_body_buf(struct gwhf_res_body_buf *buf)
{
	if (buf->buf)
		free(buf->buf);
}

void gwhf_destroy_res_body(struct gwhf_res_body *body)
{
	switch (body->type) {
	case GWHF_RES_BODY_TYPE_NONE:
		break;
	case GWHF_RES_BODY_TYPE_FD:
		destroy_res_body_fd(&body->fd);
		break;
	case GWHF_RES_BODY_TYPE_REF_FD:
		break;
	case GWHF_RES_BODY_TYPE_BUF:
		destroy_res_body_buf(&body->buf);
		break;
	case GWHF_RES_BODY_TYPE_REF_BUF:
		break;
	}

	if (body->callback_done)
		body->callback_done(body->arg);

	memset(body, 0, sizeof(*body));
	body->type = GWHF_RES_BODY_TYPE_NONE;
}

void gwhf_destroy_res_hdr(struct gwhf_res_hdr *hdr)
{
	struct gwhf_hdr_field_str *fields = hdr->fields;
	uint16_t i;

	if (!fields)
		return;

	assert(hdr->nr_fields > 0);

	for (i = 0; i < hdr->nr_fields; i++) {
		free(fields[i].key);
		free(fields[i].val);
	}

	free(hdr->fields);
	memset(hdr, 0, sizeof(*hdr));
}

void gwhf_destroy_client_res_buf(struct gwhf_client *cl)
{
	if (cl->res_buf) {
		assert(cl->res_buf_len > 0);
		free(cl->res_buf);
		cl->res_buf = NULL;
		cl->res_buf_len = 0;
		cl->res_buf_sent = 0;
	}
}
