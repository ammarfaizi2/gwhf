// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__SOCKET_H
#define GWHF__SOCKET_H

#include <gwhf/common.h>

#if defined(__linux__)
#include <arpa/inet.h>
#include <sys/socket.h>
#elif defined(WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#error "Unsupported platform"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define GWHF_INET_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof("[]:65535"))

/*
 * struct sockaddr_gwhf represents an IPv4 or IPv6 address.
 */
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
	int	type;
};
#elif defined(WIN32)
struct gwhf_sock {
	SOCKET	fd;
	int	type;
};
#endif

GWHF_EXPORT int gwhf_sock_global_init(void);
GWHF_EXPORT int gwhf_sock_global_destroy(void);
GWHF_EXPORT int gwhf_sock_create(struct gwhf_sock *sk, int af, int type,
				 int prot);
GWHF_EXPORT int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
			       socklen_t len);
GWHF_EXPORT int gwhf_sock_listen(struct gwhf_sock *sk, int backlog);
GWHF_EXPORT int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
				 struct sockaddr_gwhf *sg, socklen_t *len);
GWHF_EXPORT int gwhf_sock_connect(struct gwhf_sock *sk,
				  struct sockaddr_gwhf *dst, socklen_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__SOCKET_H */
