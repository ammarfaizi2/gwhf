// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__ROUTE_H
#define FRAMEWORK__GWHF__ROUTE_H

#include "./internal.h"

#ifdef __cplusplus
extern "C" {
#endif

int gwhf_route_init(struct gwhf *ctx);
void gwhf_route_destroy(struct gwhf *ctx);
int gwhf_route_exec_on_header(struct gwhf *ctx, struct gwhf_client *cl);
int gwhf_route_exec_on_body(struct gwhf *ctx, struct gwhf_client *cl);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef FRAMEWORK__GWHF__ROUTE_H */
