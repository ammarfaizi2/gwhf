// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__HTTP__REQUEST_H
#define GWHF__FRAMEWORK__HTTP__REQUEST_H

#include <gwhf/gwhf.h>
#include "../internal.h"

/*
 * Return the number of bytes required to store the
 * request header. From index 0 to the end of the
 * request header (including the double CRLF).
 */
int gwhf_req_hdr_parse(const char *buf, struct gwhf_req_hdr *hdr);

void gwhf_destroy_req_hdr(struct gwhf_req_hdr *hdr);
void gwhf_destroy_client_req_buf(struct gwhf_client *cl);
int gwhf_init_client_req_buf(struct gwhf_client *cl);

#endif /* GWHF__FRAMEWORK__HTTP__REQUEST_H */
