// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhf/gwhf.h>
#include <stdio.h>

#include "epoll.h"

int validate_init_arg_ev_epoll(struct gwhf_init_arg_ev_epoll *arg)
{
	if (!arg->timeout)
		arg->timeout = -1;

	if (!arg->max_events)
		arg->max_events = 8192;

	if (arg->max_events < 1)
		return -EINVAL;

	return 0;
}
