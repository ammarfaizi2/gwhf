// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H
#define FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "../../internal.h"

int gwhf_signal_init_handler(struct gwhf *ctx);
void gwhf_signal_revert_sig_handler(struct gwhf *ctx);

#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H */
