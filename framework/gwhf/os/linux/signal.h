// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H
#define FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "../internal.h"

int gwhf_init_signal_handler(struct gwhf *ctx);
void gwhf_revert_signal_handler(struct gwhf *ctx);

#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H */
