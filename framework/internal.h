// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__INTERNAL_H
#define GWHF__FRAMEWORK__INTERNAL_H

#include <gwhf/gwhf.h>
#include <stdlib.h>

#ifndef __cold
#define __cold __attribute__((__cold__))
#endif

#ifndef __hot
#define __hot __attribute__((__hot__))
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#ifndef noinline
#define noinline __attribute__((__noinline__))
#endif

#ifndef __always_inline
#define __always_inline __attribute__((__always_inline__))
#endif

enum {
	T_CLST_CLOSED       = 0,
	T_CLST_IDLE         = 1,
	T_CLST_RECV_HEADER  = 2,
	T_CLST_ROUTE_HEADER = 3,
	T_CLST_RECV_BODY    = 4,
	T_CLST_ROUTE_BODY   = 5,
	T_CLST_SEND_HEADER  = 6,
	T_CLST_SEND_BODY    = 7,
	T_CLST_END_OF_RESP  = 8,
};

struct gwhf_route_header {
	int	(*exec_cb)(struct gwhf *ctx, struct gwhf_client *cl);
};

struct gwhf_route_body {
	int	(*exec_cb)(struct gwhf *ctx, struct gwhf_client *cl);
};

struct gwhf_internal {
	struct gwhf_route_header	*route_header;
	struct gwhf_route_body		*route_body;
	uint16_t			nr_route_header;
	uint16_t			nr_route_body;
};

void gwhf_soft_reset_client(struct gwhf_client *cl);
void gwhf_reset_client(struct gwhf_client *cl);

struct gwhf_client *gwhf_get_client_slot(struct gwhf_client_slot *cs);
void gwhf_put_client_slot(struct gwhf_client_slot *cs, struct gwhf_client *cl);

void *memdup(const void *src, size_t len);
void *memdup_more(const void *src, size_t len, size_t more);
char *strtolower(char *str);
size_t url_decode(char *str, size_t len);

int gwhf_consume_recv_buffer(struct gwhf *ctx, struct gwhf_client *cl);

void gwhf_destroy_route_body(struct gwhf_internal *it);
void gwhf_destroy_route_header(struct gwhf_internal *it);

int gwhf_consume_send_buffer(struct gwhf_client *cl, const void **buf,
			     size_t *len);

void gwhf_send_buffer_advance(struct gwhf_client *cl, size_t len);

static inline struct gwhf_internal *gwhf_get_internal(struct gwhf *ctx)
{
	return ctx->internal_data;
}

#endif /* GWHF__FRAMEWORK__INTERNAL_H */
