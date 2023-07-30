// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__HTTP__RESPONSE_H
#define GWHF__FRAMEWORK__HTTP__RESPONSE_H

#include <gwhf/gwhf.h>
#include "../internal.h"

void gwhf_destroy_res_hdr(struct gwhf_res_hdr *hdr);
void gwhf_destroy_res_body(struct gwhf_res_body *body);
void gwhf_destroy_client_res_buf(struct gwhf_client *cl);
int gwhf_construct_res_buf(struct gwhf_client *cl);

#endif /* GWHF__FRAMEWORK__HTTP__RESPONSE_H */
