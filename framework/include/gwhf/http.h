// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__CLIENT_H
#define GWHF__CLIENT_H

#include "socket.h"
#include "stack.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_http_hdr_field_off {
	uint32_t	off_key;
	uint32_t	off_val;
};

enum {
	GWHF_HTTP_CONLEN_UNINITIALIZED = -1,
	GWHF_HTTP_CONLEN_NONE          = -2,
	GWHF_HTTP_CONLEN_CHUNKED       = -3,
	GWHF_HTTP_CONLEN_INVALID       = -4,
};

struct gwhf_http_req_hdr {
	struct gwhf_http_hdr_field_off	*hdr_fields;
	char		*buf;
	int64_t		content_length;
	uint32_t	buf_len;
	uint32_t	off_method;
	uint32_t	off_uri;
	uint32_t	off_qs;
	uint32_t	off_version;
	uint16_t	nr_hdr_fields;
};

struct gwhf_http_req_body {
	char		*buf;
	uint32_t	buf_len;
};

struct gwhf_http_hdr_field_str {
	char	*key;
	char	*val;
};

struct gwhf_http_res_hdr {
	struct gwhf_http_hdr_field_str	*hdr_fields;
	uint32_t	buf_len;
	uint16_t	nr_hdr_fields;
	int16_t		status;
};

enum {
	GWHF_HTTP_RES_BODY_NONE    = 0,
	GWHF_HTTP_RES_BODY_FD      = 1,
	GWHF_HTTP_RES_BODY_FD_REF  = 2,
	GWHF_HTTP_RES_BODY_BUF     = 3,
	GWHF_HTTP_RES_BODY_BUF_REF = 4,
};

struct gwhf_http_res_body_fd {
	int		fd;
	uint64_t	len;
};

struct gwhf_http_res_body_buf {
	uint8_t		*buf;
	uint64_t	len;
};

struct gwhf_http_res_body {
	uint8_t		type;
	uint64_t	off;
	void		(*callback_done)(void *arg);
	void		*cb_arg;
	union {
		struct gwhf_http_res_body_fd	fd;
		struct gwhf_http_res_body_fd	fd_ref;
		struct gwhf_http_res_body_buf	buf;
		struct gwhf_http_res_body_buf	buf_ref;
	};
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__CLIENT_H */
