// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__SOCKET_H
#define GWHF__SOCKET_H

#include <gwhf/common.h>

#if defined(__linux__)
#include <sys/socket.h>
#include <arpa/inet.h>
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winsock.h>
#endif

struct sockaddr_gwhf {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
};

#if defined(__linux__)
struct gwhf_sock {
	int	fd;
};
#elif defined(_WIN32)
struct gwhf_sock {
	SOCKET	fd;
};
#endif

GWHF_EXPORT int gwhf_sock_global_init(void);
GWHF_EXPORT void gwhf_sock_global_destroy(void);
GWHF_EXPORT int gwhf_sock_create(struct gwhf_sock *sk, int af, int type,
				 int prot);
GWHF_EXPORT int gwhf_sock_set_nonblock(struct gwhf_sock *sk);
GWHF_EXPORT int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
			       socklen_t len);
GWHF_EXPORT int gwhf_sock_listen(struct gwhf_sock *sk, int backlog);
GWHF_EXPORT int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
				 struct sockaddr_gwhf *sg, socklen_t *len);
GWHF_EXPORT int gwhf_sock_connect(struct gwhf_sock *sk,
				  struct sockaddr_gwhf *dst, socklen_t len);
GWHF_EXPORT int gwhf_sock_close(struct gwhf_sock *sk);
GWHF_EXPORT int gwhf_sock_fill_addr(struct sockaddr_gwhf *sg, const char *addr,
				    uint16_t port);

static inline socklen_t gwhf_sock_addr_len(struct sockaddr_gwhf *sg)
{
	switch (sg->sa.sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;
	}
}

#endif /* #ifndef GWHF__SOCKET_H */
