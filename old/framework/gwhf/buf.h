// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef GWHF__BUF_H
#define GWHF__BUF_H

#include "./internal.h"

#ifdef __cplusplus
extern "C" {
#endif

int gwhf_buf_init(struct gwhf_buf *b);
int gwhf_buf_init_len(struct gwhf_buf *b, size_t len);
int gwhf_buf_add_alloc(struct gwhf_buf *b, size_t add_n);
int gwhf_buf_sub_alloc(struct gwhf_buf *b, size_t sub_n);
int gwhf_buf_append(struct gwhf_buf *b, const void *data, size_t len);
void gwhf_buf_advance(struct gwhf_buf *b, size_t len);
void gwhf_buf_destroy(struct gwhf_buf *b);

static inline size_t gwhf_buf_get_free_space(struct gwhf_buf *b)
{
	return b->alloc - b->len;
}

static inline int gwhf_buf_realloc_if_needed(struct gwhf_buf *b, size_t need_n)
{
	if (b->alloc >= need_n)
		return 0;

	return gwhf_buf_add_alloc(b, need_n - b->alloc);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__BUF_H */
