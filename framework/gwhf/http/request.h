// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__HTTP__REQUEST_H
#define FRAMEWORK__GWHF__HTTP__REQUEST_H

#include "../internal.h"

int gwhf_http_req_init(struct gwhf_http_req *req);
void gwhf_http_req_destroy(struct gwhf_http_req *req);

#endif /* #ifndef FRAMEWORK__GWHF__HTTP__REQUEST_H */
