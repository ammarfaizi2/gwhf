// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#ifndef GWHF__FRAMEWORK__HTTP__RESPONSE_H
#define GWHF__FRAMEWORK__HTTP__RESPONSE_H

#include "../internal.h"

int gwhf_construct_response(struct gwhf_client *cl);

int gwhf_init_res_buf(struct gwhf_stream_res_buf *res_buf);
void gwhf_destroy_res_buf(struct gwhf_stream_res_buf *res_buf);

int gwhf_init_http_res_hdr(struct gwhf_http_res_hdr *hdr);
void gwhf_destroy_http_res_hdr(struct gwhf_http_res_hdr *hdr);

int gwhf_init_http_res_body(struct gwhf_http_res_body *body);
void gwhf_destroy_http_res_body(struct gwhf_http_res_body *body);

#endif /* #ifndef GWHF__FRAMEWORK__HTTP__RESPONSE_H */
