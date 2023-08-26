// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__INTERNAL_H
#define FRAMEWORK__GWHF__INTERNAL_H

#include <gwhf/gwhf.h>

#include "./attr.h"
#include "./thread.h"
#include "./client.h"
#include "./ev/epoll.h"
#include "./helpers.h"
#include "./http/request.h"

#if defined(__linux__)
#include "./os/linux/signal.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_worker {
	union {
		struct {
			epoll_t			ep_fd;
			evfd_t			ev_fd;
			struct epoll_event	*events;
			int			max_events;
		};
	} ev;

	struct gwhf			*ctx;
	thread_t			thread;
	uint32_t			id;
	struct gwhf_client_slot		client_slot;
	bool				is_online;
	cond_t				cond;
	mutex_t				mutex;
};

struct gwhf_internal {
	struct gwhf_sock	tcp;
	uint32_t		nr_workers;
	struct gwhf_worker	*workers;


#if defined(__linux__)
	struct sigaction	old_act[3];
#endif
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* #ifndef FRAMEWORK__GWHF__INTERNAL_H */
