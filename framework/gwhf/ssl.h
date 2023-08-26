// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__SSL_H
#define FRAMEWORK__GWHF__SSL_H

#ifndef CONFIG_HTTPS
#error "CONFIG_HTTPS is not defined"
#endif

#include "./internal.h"

#ifdef __cplusplus
extern "C" {
#endif

int gwhf_ssl_init(struct gwhf *ctx);
void gwhf_ssl_destroy(struct gwhf *ctx);
int gwhf_ssl_create_client(struct gwhf *ctx, struct gwhf_client *cl);
void gwhf_ssl_destroy_client(struct gwhf_client *cl);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef FRAMEWORK__GWHF__SSL_H */
