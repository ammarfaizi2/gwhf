// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__HTTP__RESPONSE_H
#define GWHF__FRAMEWORK__HTTP__RESPONSE_H

#include "../internal.h"

int gwhf_construct_response(struct gwhf_client *cl);

int gwhf_init_res_buf(struct gwhf_client_stream *stream);
int gwhf_init_http_res_body(struct gwhf_http_res_body *body);
int gwhf_init_http_res_hdr(struct gwhf_http_res_hdr *hdr);
void gwhf_destroy_res_buf(struct gwhf_client_stream *stream);
void gwhf_destroy_http_res_hdr(struct gwhf_http_res_hdr *hdr);
void gwhf_destroy_http_res_body(struct gwhf_http_res_body *body);

#endif /* #ifndef GWHF__FRAMEWORK__HTTP__RESPONSE_H */
