// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./buf.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

int gwhf_buf_init(struct gwhf_buf *b)
{
	return gwhf_buf_init_len(b, 4096);
}

int gwhf_buf_init_len(struct gwhf_buf *b, size_t len)
{
	char *buf;

	buf = malloc(len);
	if (!buf)
		return -ENOMEM;

	b->buf = buf;
	b->len = 0;
	b->alloc = len;
	return 0;
}

int gwhf_buf_add_alloc(struct gwhf_buf *b, size_t add_n)
{
	size_t new_alloc;
	char *new_buf;

	new_alloc = b->alloc + add_n;
	new_buf = realloc(b->buf, new_alloc);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->alloc = new_alloc;
	return 0;
}

int gwhf_buf_sub_alloc(struct gwhf_buf *b, size_t sub_n)
{
	size_t new_alloc;
	char *new_buf;

	if (b->alloc < sub_n)
		return -EINVAL;

	new_alloc = b->alloc - sub_n;
	new_buf = realloc(b->buf, new_alloc);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->alloc = new_alloc;
	return 0;
}

int gwhf_buf_append(struct gwhf_buf *b, const void *data, size_t len)
{
	int ret;

	if (b->len + len > b->alloc) {
		ret = gwhf_buf_add_alloc(b, len);
		if (ret)
			return ret;
	}

	memcpy(b->buf + b->len, data, len);
	b->len += len;
	return 0;
}

void gwhf_buf_destroy(struct gwhf_buf *b)
{
	if (!b->buf)
		return;

	free(b->buf);
	b->buf = NULL;
	memset(b, 0, sizeof(*b));
}

void gwhf_buf_advance(struct gwhf_buf *b, size_t len)
{
	size_t move_len;

	assert(b->len >= len);

	move_len = b->len - len;
	if (move_len)
		memmove(b->buf, b->buf + len, move_len);

	b->len = move_len;
}
