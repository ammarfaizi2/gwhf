// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__HTTP__RESPONSE_H
#define FRAMEWORK__GWHF__HTTP__RESPONSE_H

#include "../internal.h"

int gwhf_http_res_init(struct gwhf_http_res *req);
void gwhf_http_res_destroy(struct gwhf_http_res *req);

#endif /* #ifndef FRAMEWORK__GWHF__HTTP__RESPONSE_H */
