// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHF__EVENT__EPOLL_H
#define GWHF__EVENT__EPOLL_H

#include "../internal.h"

#if defined(__linux__)
typedef int epoll_t;
#elif defined(_WIN32)
typedef HANDLE epoll_t;
#endif

int validate_init_arg_ev_epoll(struct gwhf_init_arg_ev_epoll *arg);

#endif /* #ifndef GWHF__EVENT__EPOLL_H */
