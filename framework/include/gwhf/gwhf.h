// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__GWHF_H
#define GWHF__GWHF_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "socket.h"
#include "common.h"
#include "stack.h"
#include "http.h"

#include <time.h>
#include <sys/epoll.h>
#include <signal.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_stream_res_buf {
	char		*buf;

	/*
	 * The length of used bytes in @buf.
	 */
	uint32_t	buf_len;

	/*
	 * The number of bytes allocated for @buf.
	 */
	uint32_t	buf_alloc;

	/*
	 * The number of bytes that have been sent.
	 */
	uint32_t	off;
};

struct gwhf_stream_req_buf {
	char		*buf;

	/*
	 * The length of used bytes in @buf.
	 */
	uint32_t	buf_len;

	/*
	 * The number of bytes allocated for @buf.
	 */
	uint32_t	buf_alloc;

	int64_t		total_req_body_len;
};

struct gwhf_client_stream {
	uint8_t		state;
	char		*err_str;

	struct gwhf_stream_req_buf	req_buf;
	struct gwhf_stream_res_buf	res_buf;

	struct gwhf_http_req_hdr	req_hdr;
	struct gwhf_http_res_hdr	res_hdr;
	struct gwhf_http_res_body	res_body;
};

struct gwhf_client {
	struct gwhf_client_stream	*streams;
	void				*private_data;
	struct sockaddr_gwhf		addr;
	int				fd;
	uint32_t			nr_streams;
	struct timespec 		last_act;
	bool				pollout_set;
};

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct gwhf_stack16	stack;
};

enum {
	GWHF_EV_TYPE_DEFAULT  = 0,
	GWHF_EV_TYPE_SELECT   = 1,
	GWHF_EV_TYPE_POLL     = 2,
	GWHF_EV_TYPE_EPOLL    = 3,
	GWHF_EV_TYPE_KQUEUE   = 4,
	GWHF_EV_TYPE_IO_URING = 5,
};

struct gwhf_init_arg_ev_epoll {
	uint16_t	max_events;
	int		timeout;
};

struct gwhf_init_arg {
	uint8_t		ev_type;
	char		bind_addr[INET6_ADDRSTRLEN];
	uint16_t	nr_clients;
	uint16_t	bind_port;
	int		listen_backlog;

	union {
		struct gwhf_init_arg_ev_epoll	epoll;
	} ev;
};

struct gwhf_ev_epoll {
	struct epoll_event 	*events;
	int			epoll_fd;
	int			event_fd;
	int			timeout;
	uint16_t		max_events;
};

struct gwhf {
	volatile bool			stop;

	/*
	 * The main TCP socket for accepting new connections.
	 */
	struct gwhf_sock_tcp		tcp;

	/*
	 * For QUIC support later. It is not implemented yet.
	 */
	struct gwhf_sock_udp		udp;

	struct gwhf_client_slot		client_slot;

	union {
		struct gwhf_ev_epoll	ev_epoll;
	};

	void				*internal_data;
	struct timespec			now;
	struct gwhf_init_arg		init_arg;
	struct sigaction		old_act[3];
};

GWHF_EXPORT int gwhf_init_arg(struct gwhf *ctx, const struct gwhf_init_arg *arg);
GWHF_EXPORT int gwhf_init(struct gwhf *ctx);
GWHF_EXPORT void gwhf_destroy(struct gwhf *ctx);
GWHF_EXPORT int gwhf_run(struct gwhf *ctx);

GWHF_EXPORT int gwhf_add_route_header(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *));
GWHF_EXPORT int gwhf_add_route_body(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__GWHF_H */
