// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__HTTP__STREAM_H
#define GWHF__FRAMEWORK__HTTP__STREAM_H

#include "../internal.h"
#include "response.h"
#include "request.h"

int gwhf_init_client_streams(struct gwhf_client *cl, uint32_t nr_streams);
void gwhf_destroy_client_streams(struct gwhf_client *cl);

/*
 * Use this for reusing the stream when keep-alive is enabled
 * to avoid destroying and reinitializing the stream.
 */
void gwhf_soft_reset_client_streams(struct gwhf_client *cl);

#endif /* #ifndef GWHF__FRAMEWORK__HTTP__STREAM_H */
