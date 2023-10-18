// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H
#define FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H

#include "../../internal.h"

static inline int gwhf_signal_init_handler(struct gwhf *ctx)
{
        return 0;
}

static inline void gwhf_signal_revert_sig_handler(struct gwhf *ctx)
{
}

#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__SIGNAL_H */
