// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__HTTP__REQUEST_H
#define FRAMEWORK__GWHF__HTTP__REQUEST_H

#include "../internal.h"

int gwhf_http_req_init(struct gwhf_http_req *req);
void gwhf_http_req_destroy(struct gwhf_http_req *req);
int gwhf_http_req_parse_header(struct gwhf_http_req_hdr *hdr, const char *buf,
			       size_t len);

#endif /* #ifndef FRAMEWORK__GWHF__HTTP__REQUEST_H */
