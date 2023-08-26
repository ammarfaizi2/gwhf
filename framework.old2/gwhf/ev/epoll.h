// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef GWHF__EV__EPOLL_H
#define GWHF__EV__EPOLL_H

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
#include "../client.h"

struct gwhf_worker;

int gwhf_ev_epoll_validate_init_arg(struct gwhf_init_arg_ev_epoll *arg);
int gwhf_ev_epoll_init_worker(struct gwhf_worker *wrk);
void gwhf_ev_epoll_destroy_worker(struct gwhf_worker *wrk);
int gwhf_ev_epoll_run_worker(struct gwhf_worker *wrk);

#endif /* #ifndef GWHF__EV__EPOLL_H */
