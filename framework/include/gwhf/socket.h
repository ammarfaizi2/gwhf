// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__SOCKET_H
#define GWHF__SOCKET_H

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "common.h"

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

struct gwhf_sock_tcp {
	int fd;
};

struct gwhf_sock_udp {
	int fd;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__SOCKET_H */
