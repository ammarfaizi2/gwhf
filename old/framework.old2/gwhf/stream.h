// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__STREAM_H
#define FRAMEWORK__GWHF__STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "./internal.h"

int gwhf_stream_init_all(struct gwhf_client *cl, uint32_t nr_streams);
int gwhf_stream_init(struct gwhf_client_stream *str);

void gwhf_stream_destroy_all(struct gwhf_client *cl);
void gwhf_stream_destroy(struct gwhf_client_stream *str);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* #ifndef FRAMEWORK__GWHF__STREAM_H */
