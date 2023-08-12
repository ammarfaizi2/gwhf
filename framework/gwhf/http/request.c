// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <string.h>
#include <stddef.h>

#include "request.h"

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

int gwhf_http_req_init(struct gwhf_http_req *req)
{
	assert(req->hdr.content_length == GWHF_CONLEN_UNSET ||
	       req->hdr.content_length == 0);

	memset(req, 0, sizeof(*req));
	return 0;
}

static void gwhf_http_req_hdr_destroy(struct gwhf_http_req_hdr *hdr)
{
	if (hdr->buf)
		free(hdr->buf);

	if (hdr->hdr_fields)
		free(hdr->hdr_fields);

	memset(hdr, 0, sizeof(*hdr));
	hdr->content_length = GWHF_CONLEN_UNSET;
}

static void gwhf_http_req_body_destroy(struct gwhf_http_req *req)
{
	(void)req;
}

void gwhf_http_req_destroy(struct gwhf_http_req *req)
{
	gwhf_http_req_hdr_destroy(&req->hdr);
	gwhf_http_req_body_destroy(req);
	memset(req, 0, sizeof(*req));
}
