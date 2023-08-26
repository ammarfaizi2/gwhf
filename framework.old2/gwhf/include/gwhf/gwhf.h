// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__GWHF_H
#define FRAMEWORK__GWHF__INCLUDE__GWHF__GWHF_H

#include <gwhf/common.h>
#include <gwhf/socket.h>
#include <gwhf/stack.h>
#include <gwhf/client.h>

enum {
	GWHF_EV_DEFAULT  = 0,
	GWHF_EV_EPOLL    = 1,
	GWHF_EV_KQUEUE   = 2,
	GWHF_EV_POLL     = 3,
	GWHF_EV_SELECT   = 4,
	GWHF_EV_IO_URING = 5
};

struct gwhf_init_arg_ev_epoll {
	int		max_events;
	int		timeout;
};

struct gwhf_init_arg {
	const char	*bind_addr;
	uint32_t	nr_workers;
	int		backlog;
	uint16_t	bind_port;
	uint16_t	max_clients;
	uint8_t		ev_type;

	union {
		struct gwhf_init_arg_ev_epoll	ev_epoll;
	};
};

struct gwhf_internal;

struct gwhf {
	volatile bool		stop;
	bool			stop_accepting;
	struct gwhf_internal	*internal;
	struct gwhf_init_arg	init_arg;
};

GWHF_EXPORT int gwhf_global_init(void);
GWHF_EXPORT void gwhf_global_destroy(void);
GWHF_EXPORT int gwhf_init(struct gwhf *ctx);
GWHF_EXPORT int gwhf_init_arg(struct gwhf *ctx, const struct gwhf_init_arg *arg);
GWHF_EXPORT int gwhf_run(struct gwhf *ctx);
GWHF_EXPORT void gwhf_destroy(struct gwhf *ctx);
GWHF_EXPORT const char *gwhf_strerror(int err);

#endif /* #ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__GWHF_H */
