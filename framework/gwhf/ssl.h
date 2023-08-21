// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__SSL_H
#define FRAMEWORK__GWHF__SSL_H

#include <gwhf/client.h>

int gwhf_ssl_buf_init(struct gwhf_ssl_buffer *buf);
void gwhf_ssl_buf_free(struct gwhf_ssl_buffer *buf);

#endif /* #ifndef FRAMEWORK__GWHF__SSL_H */
