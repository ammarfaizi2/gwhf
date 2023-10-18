// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__SSL_H
#define FRAMEWORK__GWHF__SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "./internal.h"

int gwhf_ssl_init(struct gwhf *ctx);
void gwhf_ssl_destroy(struct gwhf *ctx);
int gwhf_ssl_init_client(struct gwhf *ctx, struct gwhf_client *cl);
void gwhf_ssl_destroy_client(struct gwhf_client *cl);

#endif /* #ifndef FRAMEWORK__GWHF__SSL_H */
