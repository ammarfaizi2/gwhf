// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int gwhf_http_req_init(struct gwhf_http_req *req)
{
	memset(req, 0, sizeof(*req));
	req->hdr.content_length = GWHF_CONLEN_UNSET;
	return 0;
}

void gwhf_http_req_destroy(struct gwhf_http_req *req)
{
	if (req->hdr.buf)
		free(req->hdr.buf);

	if (req->hdr.hdr_fields)
		free(req->hdr.hdr_fields);

	memset(req, 0, sizeof(*req));
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
