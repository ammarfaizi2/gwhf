// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHF__TLS_H
#define GWHF__TLS_H

#include <gwhf/client.h>

int gwhf_tls_buf_init(struct gwhf_tls_buffer *buf);
void gwhf_tls_buf_free(struct gwhf_tls_buffer *buf);

#endif /* #ifndef GWHF__TLS_H */
