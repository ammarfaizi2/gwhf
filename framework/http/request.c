// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "request.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define GWHF_CLIENT_BUF_SIZE 8192

char *gwhf_req_hdr_get_field(struct gwhf_req_hdr *hdr, const char *key)
{
	char *ret = NULL;
	uint16_t i;

	for (i = 0; i < hdr->nr_fields; i++) {
		struct gwhf_hdr_field_off *field;
		char *fkkey;

		field = &hdr->fields[i];
		fkkey = hdr->buf + field->off_key;

		if (strcasecmp(fkkey, key) == 0) {
			ret = hdr->buf + field->off_val;
			break;
		}
	}

	return ret;
}

static int parse_method_uri_version_qs(struct gwhf_req_hdr *hdr,
				       char **second_line)
{
	char *buf, *end, *ptr;

	assert(!hdr->off_method);
	assert(!hdr->off_uri);
	assert(!hdr->off_version);
	assert(!hdr->off_qs);

	buf = hdr->buf;
	ptr = strchr(buf, '\r');
	ptr[0] = '\0';

	if (ptr[1] != '\n')
		return -EINVAL;

	*second_line = &ptr[2];

	/*
	 * Extract the method.
	 */
	hdr->off_method = 0u;
	end = strchr(buf, ' ');
	if (!end)
		return -EINVAL;

	*end++ = '\0';

	/*
	 * Extract the URI.
	 */
	hdr->off_uri = (uint32_t)(end - buf);
	if (end[0] != '/')
		return -EINVAL;

	end = strchr(end, ' ');
	if (!end)
		return -EINVAL;

	*end++ = '\0';


	/*
	 * Extract the query string.
	 */
	hdr->off_qs = -1;
	ptr = strchr(&buf[hdr->off_uri], '?');
	if (ptr) {
		hdr->off_qs = (uint32_t)(ptr - buf + 1u);
		*ptr++ = '\0';
	}

	/*
	 * Extract the HTTP version.
	 */
	hdr->off_version = (uint32_t)(end - buf);
	if (strncmp(end, "HTTP/", 5u))
		return -EINVAL;

	return 0;
}

static int parse_hdr_req_fields(char *buf, struct gwhf_req_hdr *hdr)
{
	struct gwhf_hdr_field_off *tmp, *fields = NULL;
	uint16_t nr_fields = 0u;
	uint16_t nr_alloc = 16u; /* Don't realloc() too often. */
	char *ptr, *end;
	int err;

	assert(!hdr->fields);
	assert(!hdr->nr_fields);
	assert(hdr->content_length == GWHF_CONTENT_LENGTH_UNINITIALIZED);

	ptr = buf;
	if (!ptr[0])
		return 0;

	fields = malloc(nr_alloc * sizeof(*fields));
	if (!fields)
		return -ENOMEM;

	hdr->content_length = GWHF_CONTENT_LENGTH_NOT_PRESENT;
	err = -EINVAL;
	while (ptr[0]) {
		char *key, *val;

		if (ptr[0] == '\r' && ptr[1] == '\n')
			break;

		nr_fields++;

		if (nr_fields > nr_alloc) {
			nr_alloc *= 2;
			tmp = realloc(fields, nr_alloc * sizeof(*fields));
			if (!tmp) {
				err = -ENOMEM;
				goto out_err;
			}
			fields = tmp;
		}

		tmp = &fields[nr_fields - 1];
		tmp->off_key = (uint16_t)(ptr - hdr->buf);

		end = strchr(ptr, ':');
		if (!end)
			goto out_err;

		key = strtolower(ptr);
		*end++ = '\0';
		tmp->off_val = (uint16_t)(end - hdr->buf + 1u);

		val = end;
		ptr = strchr(end, '\r');
		if (!ptr)
			goto out_err;

		*ptr = '\0';
		if (ptr[1] != '\n')
			goto out_err;

		if (!strcmp("content-length", key)) {
			char *eptr;
			int64_t cl;

			cl = (int64_t)strtoll(val, &eptr, 10);
			if (eptr[0] != '\0')
				cl = GWHF_CONTENT_LENGTH_INVALID;

			hdr->content_length = cl;
		} else if (!strcmp("transfer-encoding", key) && !strcmp("chunked", val)) {
			hdr->content_length = GWHF_CONTENT_LENGTH_CHUNKED;
		}

		ptr += 2;
	}

	hdr->fields = fields;
	hdr->nr_fields = nr_fields;
	return 0;

out_err:
	free(fields);
	return err;
}

int gwhf_req_hdr_parse(const char *buf, struct gwhf_req_hdr *hdr)
{
	char *crlf, *second_line;
	uint16_t len;
	int ret;

	crlf = strstr(buf, "\r\n\r\n");
	if (unlikely(!crlf)) {
		/*
		 * The request header is not complete yet.
		 */
		return -EAGAIN;
	}

	len = (uint16_t)(crlf - buf) + 4u;
	hdr->buf = memdup_more(buf, len, 1);
	if (unlikely(!hdr->buf))
		return -ENOMEM;

	hdr->buf_len = len;
	hdr->buf[len] = '\0';

	/*
	 * The first line contains the method, URI, and HTTP version.
	 *
	 * It's something like this:
	 * "GET / HTTP/1.1\r\n"
	 *
	 */
	ret = parse_method_uri_version_qs(hdr, &second_line);
	if (unlikely(ret < 0))
		goto err;

	/*
	 * The second line contains the request header fields.
	 */
	ret = parse_hdr_req_fields(second_line, hdr);
	if (unlikely(ret < 0))
		goto err;

	return (int)ret;

err:
	free(hdr->buf);
	memset(hdr, 0, sizeof(*hdr));
	hdr->content_length = GWHF_CONTENT_LENGTH_UNINITIALIZED;
	return ret;
}

void gwhf_destroy_req_hdr(struct gwhf_req_hdr *hdr)
{
	if (hdr->fields) {
		assert(hdr->nr_fields > 0);
		free(hdr->fields);
		hdr->fields = NULL;
		hdr->nr_fields = 0;
	}

	if (hdr->buf) {
		assert(hdr->buf_len > 0);
		free(hdr->buf);
		hdr->buf = NULL;
		hdr->buf_len = 0;
	}

	memset(hdr, 0, sizeof(*hdr));
	hdr->content_length = GWHF_CONTENT_LENGTH_UNINITIALIZED;
}

void gwhf_destroy_client_req_buf(struct gwhf_client *cl)
{
	if (cl->req_buf) {
		assert(cl->req_buf_len > 0);
		free(cl->req_buf);
		cl->req_buf = NULL;
		cl->req_buf_len = 0;
		cl->req_buf_off = 0;
	}
}

int gwhf_init_client_req_buf(struct gwhf_client *cl)
{
	char *req_buf;

	req_buf = malloc(GWHF_CLIENT_BUF_SIZE);
	if (!req_buf)
		return -ENOMEM;

	cl->req_buf = req_buf;
	cl->req_buf_len = GWHF_CLIENT_BUF_SIZE;
	cl->req_buf_off = 0;
	return 0;
}
