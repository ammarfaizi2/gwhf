// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__GWHF_H
#define GWHF__GWHF_H

#include "socket.h"
#include "common.h"
#include "stack.h"
#include "http.h"

#ifdef __cplusplus
extern "C" {
#endif
struct gwhf_client_stream {
	char		*req_buf;
	char		*res_buf;

	uint32_t	req_buf_alloc;
	uint32_t	res_buf_alloc;

	uint32_t	req_buf_len;
	uint32_t	res_buf_len;

	uint32_t	res_buf_sent;

	struct gwhf_http_req_hdr	req_hdr;
	struct gwhf_http_req_body	req_body;
	struct gwhf_http_res_hdr	res_hdr;
	struct gwhf_http_res_body	res_body;
};

struct gwhf_client {
	struct gwhf_client_stream	*streams;
	struct sockaddr_gwhf		addr;
	int				fd;
	uint32_t			nr_streams;
};

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct gwhf_stack16	stack;
};

struct gwhf {
	struct gwhf_sock_tcp		tcp;
	struct gwhf_sock_udp		udp;
	struct gwhf_client_slot		client_slot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__GWHF_H */
