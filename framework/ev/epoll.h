// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__EV__EPOLL_H
#define GWHF__FRAMEWORK__EV__EPOLL_H

#include "../internal.h"
#include "../client.h"
#include "../stream.h"

int gwhf_validate_and_adjust_init_arg_ev_epoll(struct gwhf_init_arg *arg);
int gwhf_init_ev_epoll(struct gwhf *ctx);
void gwhf_destroy_ev_epoll(struct gwhf *ctx);
int gwhf_run_ev_epoll(struct gwhf *ctx);

#endif /* GWHF__FRAMEWORK__EV__EPOLL_H */
