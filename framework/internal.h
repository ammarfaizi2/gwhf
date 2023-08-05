// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__INTERNAL_H
#define GWHF__FRAMEWORK__INTERNAL_H

#include <gwhf/gwhf.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#include "helpers.h"

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
	T_CL_STREAM_OFF             = 0,
	T_CL_STREAM_IDLE            = (1u << 0u),

	T_CL_STREAM_RECV_HEADER     = (1u << 1u),
	T_CL_STREAM_ROUTE_HEADER    = (1u << 2u),
	T_CL_STREAM_RECV_BODY       = (1u << 3u),
	T_CL_STREAM_ROUTE_BODY      = (1u << 4u),

	T_CL_STREAM_SEND_HEADER     = (1u << 5u),
	T_CL_STREAM_SEND_BODY       = (1u << 6u),
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

static inline struct gwhf_internal *gwhf_get_internal(struct gwhf *ctx)
{
	return ctx->internal_data;
}

void gwhf_destroy_route_header(struct gwhf_internal *it);
void gwhf_destroy_route_body(struct gwhf_internal *it);
int gwhf_exec_route_body(struct gwhf *ctx, struct gwhf_client *cl);
int gwhf_exec_route_header(struct gwhf *ctx, struct gwhf_client *cl);

int gwhf_init_client_slot(struct gwhf *ctx);
void gwhf_destroy_client_slot(struct gwhf *ctx);

void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl);
void gwhf_reset_client(struct gwhf_client *cl);

int gwhf_consume_client_recv_buf(struct gwhf *ctx, struct gwhf_client *cl);
int gwhf_get_client_send_buf(struct gwhf *ctx, struct gwhf_client *cl,
			     const void **buf, size_t *len);
void gwhf_client_send_buf_advance(struct gwhf_client *cl, size_t len);

#endif /* #ifndef GWHF__FRAMEWORK__INTERNAL_H */
