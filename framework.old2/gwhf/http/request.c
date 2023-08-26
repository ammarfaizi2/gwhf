// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./request.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

int gwhf_http_req_init(struct gwhf_http_req *req)
{
	memset(req, 0, sizeof(*req));

	req->body = malloc(4096);
	if (!req->body)
		return -ENOMEM;

	req->body_alloc = 4096;
	req->body_len = 0;
	req->hdr.content_length = GWHF_CONLEN_UNSET;
	return 0;
}

void gwhf_http_req_destroy(struct gwhf_http_req *req)
{
	if (req->hdr.buf)
		free(req->hdr.buf);

	if (req->hdr.hdr_fields)
		free(req->hdr.hdr_fields);

	if (req->body)
		free(req->body);

	memset(req, 0, sizeof(*req));
}

int gwhf_http_req_body_add(struct gwhf_http_req *req, const void *buf,
			   uint32_t len)
{
	uint32_t new_len = req->body_len + len;

	if (unlikely(new_len > req->body_alloc)) {
		uint32_t new_alloc = req->body_alloc * 2u;
		char *new_buf;

		while (new_len > new_alloc)
			new_alloc *= 2u;

		new_buf = realloc(req->body, new_alloc);
		if (unlikely(!new_buf))
			return -ENOMEM;

		req->body = new_buf;
		req->body_alloc = new_alloc;
	}

	memcpy(req->body + req->body_len, buf, len);
	req->body_len = new_len;
	return 0;
}

const char *gwhf_http_req_get_hdr(struct gwhf_http_req *req, const char *key)
{
	struct gwhf_http_hdr_field_off *hdr_fields = req->hdr.hdr_fields;
	uint16_t i = req->hdr.nr_hdr_fields;

	while (i--) {
		if (!gwhf_strcmpi(req->hdr.buf + hdr_fields->off_key, key))
			return req->hdr.buf + hdr_fields->off_val;

		hdr_fields++;
	}

	return NULL;
}

static char *trim_spaces_forward(char *p)
{
	char *start = p;

	while (1) {
		char c = *p;

		if (!c)
			break;

		if (c != ' ' && c != '\t' && c != '\r')
			break;

		p++;
	}

	if (start != p)
		start[0] = '\0';

	return p;
}

static char *trim_spaces_backward(char *p)
{
	char *start = p;

	while (1) {
		char c = *p;

		if (!c)
			break;

		if (c != ' ' && c != '\t' && c != '\r')
			break;
		
		p--;
	}

	if (start != p)
		p[1] = '\0';

	return p;
}

static char *find_space(char *p)
{
	while (1) {
		char c = *p;

		if (!c)
			return NULL;

		if (c == ' ' || c == '\t' || c == '\r')
			return p;

		p++;
	}
}

static int parse_method_uri_qs_version(char **next,
				       struct gwhf_http_req_hdr *hdr)
{
	char *p, *head, *tail, *end;

	head = *next;
	end = strchr(head, '\n');
	if (!end)
		return -EINVAL;

	*next = &end[1];

	/*
	 * Kill trailing spaces. If there are no spaces, then assume the
	 * line ends with an LF, not a CRLF. Kill the LF or the first
	 * space after the HTTP version string.
	 */
	if (trim_spaces_backward(end - 1) == end - 1)
		*end = '\0';

	/*
	 * Parse the method. The method ends with a space.
	 */
	head = trim_spaces_forward(head);
	tail = find_space(head);
	if (!tail)
		return -EINVAL;

	/*
	 * Make sure the method is uppercase.
	 */
	p = head;
	while (1) {
		char c = *p++;

		if (p == tail)
			break;

		if (c < 'A' || c > 'Z')
			return -EINVAL;
	}

	hdr->off_method = (uint32_t)(head - hdr->buf);


	/*
	 * Parse the URI.
	 */
	head = trim_spaces_forward(tail);
	if (head >= end)
		return -EINVAL;

	tail = find_space(head);
	if (!tail)
		return -EINVAL;

	hdr->off_uri = (uint32_t)(head - hdr->buf);


	/*
	 * Parse the HTTP version string.
	 */
	head = trim_spaces_forward(tail);
	if (head >= end)
		return -EINVAL;

	if (strncmp(head, "HTTP/", 5))
		return -EINVAL;

	hdr->off_version = (uint32_t)(head - hdr->buf);


	/*
	 * Try to parse the query string. The query string starts with a
	 * question mark and ends with a space.
	 */
	p = strchr(&hdr->buf[hdr->off_uri], '?');
	if (p) {
		p[0] = '\0';
		hdr->off_qs = (uint32_t)(p + 1 - hdr->buf);
	} else {
		hdr->off_qs = (uint32_t)-1;
	}

	return 0;
}

static int parse_http_header_fields(char **next, struct gwhf_http_req_hdr *hdr)
{
	int64_t conlen = GWHF_CONLEN_NOT_PRESENT;
	struct gwhf_http_hdr_field_off *fields;
	uint16_t alloc_fields = 16;
	uint16_t nr_fields = 0;
	char *p, *head, *tail;

	head = *next;
	tail = strchr(head, '\n');
	assert(tail);

	fields = malloc(alloc_fields * sizeof(*fields));
	if (!fields)
		return -ENOMEM;

	assert(hdr->content_length == GWHF_CONLEN_UNSET);
	while (1) {
		struct gwhf_http_hdr_field_off *tmp;
		char *kstr, *vstr;

		head = trim_spaces_forward(head);
		if (*head == '\n')
			break;

		/*
		 * Realloc if needed.
		 */
		if (unlikely(nr_fields == alloc_fields)) {
			alloc_fields += 16;
			tmp = realloc(fields, alloc_fields * sizeof(*fields));
			if (!tmp) {
				free(fields);
				return -ENOMEM;
			}

			fields = tmp;
		}

		tmp = &fields[nr_fields];

		/*
		 * Save the key offset.
		 */
		tmp->off_key = (uint32_t)(head - hdr->buf);

		/*
		 * Find the key-val separator.
		 */
		head = strchr(head, ':');
		if (!head)
			goto out_err;

		trim_spaces_backward(head - 1);
		*head++ = '\0';

		p = trim_spaces_forward(head);
		if (*p != '\n') {
			/*
			 * If *p is '\n', then the value is empty.
			 * Otherwise, the value starts at p.
			 */
			head = p;
		}

		/*
		 * Save the value offset.
		 */
		tmp->off_val = (uint32_t)(head - hdr->buf);

		/*
		 * TODO(ammarfaizi2): Rewrite this mess.
		 */
		kstr = hdr->buf + tmp->off_key;
		vstr = hdr->buf + tmp->off_val;
		if (!gwhf_strcmpi("content-length", kstr)) {
			char *end;
			if (conlen != GWHF_CONLEN_NOT_PRESENT) {
				conlen = GWHF_CONLEN_INVALID;
			} else {
				conlen = strtoll(vstr, &end, 10);
				if (conlen < 0 || *end != '\0')
					conlen = GWHF_CONLEN_INVALID;
			}
		} else if (!gwhf_strcmpi("transfer-encoding", kstr)) {
			if (conlen != GWHF_CONLEN_NOT_PRESENT) {
				conlen = GWHF_CONLEN_INVALID;
			} else {
				if (!gwhf_strcmpi("chunked", vstr))
					conlen = GWHF_CONLEN_CHUNKED;
				else
					conlen = GWHF_CONLEN_INVALID;
			}
		}

		nr_fields++;

		/*
		 * Trim the value from the right.
		 */
		p = trim_spaces_backward(tail - 1);
		if (p == tail - 1) {
			/*
			 * If p == tail - 1, then the EOL is an LF.
			 */
			*tail = '\0';
		}

		/*
		 * Start parsing the next field.
		 */
		head = ++tail;
		tail = strchr(head, '\n');
		if (!tail)
			goto out_err;
	}

	if (!nr_fields) {
		free(fields);
		fields = NULL;
	}

	hdr->content_length = conlen;
	hdr->nr_hdr_fields = nr_fields;
	hdr->hdr_fields = fields;
	*next = &tail[1];
	return 0;

out_err:
	free(fields);
	return -EINVAL;
}

int gwhf_http_req_parse_header(struct gwhf_http_req_hdr *hdr, const char *buf,
			       size_t buf_len)
{
	uint32_t len;
	char *dcrlf;
	char *hbuf;
	char *next;
	int ret;

	if (unlikely(buf_len < 4))
		return -EAGAIN;

	if (unlikely(buf[buf_len - 1] != '\0'))
		return -EINVAL;

	dcrlf = strstr(buf, "\r\n\r\n");
	if (unlikely(!dcrlf)) {
		dcrlf = strstr(buf, "\n\n");
		if (!dcrlf) {
			if (buf_len > UINT16_MAX)
				return -E2BIG;

			return -EAGAIN;
		}
	}

	len = dcrlf - buf + 4;
	hbuf = memdup_more(buf, len, 1);
	if (unlikely(!hbuf))
		return -ENOMEM;

	hbuf[len] = '\0';
	hdr->buf = hbuf;
	hdr->len = len;
	next = hbuf;
	dcrlf = &hbuf[len - 4];

	ret = parse_method_uri_qs_version(&next, hdr);
	if (unlikely(ret < 0))
		goto out_err;

	ret = parse_http_header_fields(&next, hdr);
	if (unlikely(ret < 0))
		goto out_err;

	return 0;

out_err:
	free(hdr->buf);
	hdr->buf = NULL;
	hdr->len = 0;
	return ret;
}
