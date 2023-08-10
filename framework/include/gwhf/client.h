// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__CLIENT_H
#define GWHF__CLIENT_H

#include <gwhf/common.h>
#include <gwhf/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_client_stream {

};

struct gwhf_ssl_buffer {
	char		*buf;
	uint32_t	len;
	uint32_t	alloc;
};

struct gwhf_client {
	/*
	 * The socket file descriptor (TCP only).
	 */
	struct gwhf_sock		fd;

	/*
	 * Client source address.
	 */
	struct sockaddr_gwhf		addr;

	/*
	 * SSL buffer.
	 */
	struct gwhf_ssl_buffer		ssl_buf;

	/*
	 * Stream array.
	 */
	struct gwhf_client_stream	*streams;

	/*
	 * The number of streams.
	 */
	uint32_t			nr_streams;

	/*
	 * The index of current used stream.
	 */
	uint32_t			cur_stream;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__CLIENT_H */
