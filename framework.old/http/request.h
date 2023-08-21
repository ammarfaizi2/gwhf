// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#ifndef GWHF__FRAMEWORK__HTTP__REQUEST_H
#define GWHF__FRAMEWORK__HTTP__REQUEST_H

#include "../internal.h"

/*
 * Return the number of bytes required to store the
 * request header. From index 0 to the end of the
 * request header (including the double CRLF).
 *
 * Return -EAGAIN if the request header is not yet
 * complete.
 * 
 * Return -ENOMEM if the memory allocation failed.
 * 
 * Return -EINVAL if the request header is invalid.
 */
int gwhf_parse_http_req_hdr(const char *buf, size_t buf_len,
			    struct gwhf_http_req_hdr *hdr);

int gwhf_init_req_buf(struct gwhf_stream_req_buf *req_buf);
void gwhf_destroy_req_buf(struct gwhf_stream_req_buf *req_buf);

int gwhf_init_http_req_hdr(struct gwhf_http_req_hdr *hdr);
void gwhf_destroy_http_req_hdr(struct gwhf_http_req_hdr *hdr);

#endif /* GWHF__FRAMEWORK__HTTP__REQUEST_H */
