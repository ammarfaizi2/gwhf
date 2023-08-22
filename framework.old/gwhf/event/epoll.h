// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__EVENT__EPOLL_H
#define FRAMEWORK__GWHF__EVENT__EPOLL_H

#include <gwhf/gwhf.h>

#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
typedef int epoll_t;
typedef int evfd_t;

static inline int epoll_close(epoll_t epfd)
{
	return close(epfd);
}
#elif defined(_WIN32) /* #if defined(__linux__) */
#include "../ext/wepoll/wepoll.h"
typedef HANDLE epoll_t;
typedef struct {
	struct gwhf_sock write;
	struct gwhf_sock read;
} evfd_t;
#endif /* #if defined(__linux__) */

#include "../internal.h"

struct gwhf_worker;

int validate_init_arg_ev_epoll(struct gwhf_init_arg_ev_epoll *arg);
int gwhf_init_worker_ev_epoll(struct gwhf_worker *wrk);
int gwhf_run_worker_ev_epoll(struct gwhf_worker *wrk);
int gwhf_destroy_worker_ev_epoll(struct gwhf_worker *wrk);

#endif /* #ifndef FRAMEWORK__GWHF__EVENT__EPOLL_H */
