// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "response.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
		cl->res_buf_off = 0;
	}
}
