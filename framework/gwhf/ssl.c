// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#include <string.h>

#include "internal.h"
#include "ssl.h"

int gwhf_ssl_buf_init(struct gwhf_ssl_buffer *sbuf)
{
	uint32_t alloc = 4096;
	char *buf;

	buf = malloc(alloc);
	if (unlikely(!buf))
		return -ENOMEM;

	sbuf->alloc = alloc;
	sbuf->len = 0;
	sbuf->buf = buf;
	return 0;
}

void gwhf_ssl_buf_free(struct gwhf_ssl_buffer *sbuf)
{
	if (!sbuf->buf)
		return;

	free(sbuf->buf);
	memset(sbuf, 0, sizeof(*sbuf));
}
