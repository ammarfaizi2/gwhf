// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhf/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int gwhf_sock_global_init(void)
{
	return 0;
}

void gwhf_sock_global_destroy(void)
{
}

int gwhf_sock_create(struct gwhf_sock *sk, int af, int type, int prot)
{
	int fd;

	fd = socket(af, type, prot);
	if (fd < 0)
		return -errno;

	sk->fd = fd;
	return 0;
}

int gwhf_sock_set_nonblock(struct gwhf_sock *sk)
{
	int ret;

	ret = fcntl(sk->fd, F_GETFL);
	if (ret < 0)
		return -errno;

	ret = fcntl(sk->fd, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
		   socklen_t len)
{
	int ret;

	ret = bind(sk->fd, &sg->sa, len);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_listen(struct gwhf_sock *sk, int backlog)
{
	int ret;

	ret = listen(sk->fd, backlog);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
		     struct sockaddr_gwhf *sg, socklen_t *len)
{
	int fd;

	fd = accept(sk->fd, &sg->sa, len);
	if (fd < 0)
		return -errno;

	ret->fd = fd;
	return 0;
}

int gwhf_sock_connect(struct gwhf_sock *sk, struct sockaddr_gwhf *dst,
		      socklen_t len)
{
	int ret;

	ret = connect(sk->fd, &dst->sa, len);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_close(struct gwhf_sock *sk)
{
	int ret;

	if (sk->fd < 0)
		return 0;

	ret = close(sk->fd);
	if (ret < 0)
		return -errno;

	sk->fd = -1;
	return 0;
}

int gwhf_sock_fill_addr(struct sockaddr_gwhf *sg, const char *addr,
			uint16_t port)
{
	struct sockaddr_in6 *in6 = &sg->sin6;
	struct sockaddr_in *in = &sg->sin;
	int ret;

	memset(sg, 0, sizeof(*sg));
	ret = inet_pton(AF_INET6, addr, &in6->sin6_addr);
	if (ret == 1) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET, addr, &in->sin_addr);
	if (ret == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		return 0;
	}

	return -EINVAL;
}
