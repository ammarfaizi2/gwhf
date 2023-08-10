// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <string.h>

#include "internal.h"
#include "tls.h"

int gwhf_tls_buf_init(struct gwhf_tls_buffer *tbuf)
{
	uint32_t alloc = 4096;
	char *buf;

	buf = malloc(alloc);
	if (!buf)
		return -ENOMEM;

	tbuf->alloc = alloc;
	tbuf->len = 0;
	tbuf->buf = buf;
	return 0;
}

void gwhf_tls_buf_free(struct gwhf_tls_buffer *tbuf)
{
	if (!tbuf->buf)
		return;

	free(tbuf->buf);
	memset(tbuf, 0, sizeof(*tbuf));
}
