// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__EV__EPOLL_H
#define GWHF__FRAMEWORK__EV__EPOLL_H

#include <gwhf/gwhf.h>

int gwhf_run_event_loop_epoll(struct gwhf *ctx);
int epoll_add(int epfd, int fd, uint32_t events, union epoll_data data);
int epoll_del(int epfd, int fd);
int epoll_mod(int epfd, int fd, uint32_t events, union epoll_data data);
int validate_and_adjust_ev_epoll_arg(struct gwhf_init_arg *arg);
void destroy_event_loop_epoll(struct gwhf_epoll *ep);
int init_event_loop_epoll(struct gwhf *ctx);

#endif /* GWHF__FRAMEWORK__EV__EPOLL_H */
