// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhf/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int gwhf_sock_global_init(void)
{
	WSADATA wsa_data;
	int ret;

	ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (ret)
		return ret;

	return 0;
}

void gwhf_sock_global_destroy(void)
{
	WSACleanup();
}

int gwhf_sock_create(struct gwhf_sock *sk, int af, int type, int prot)
{
	SOCKET fd;

	fd = socket(af, type, prot);
	if (fd == INVALID_SOCKET)
		return WSAGetLastError();

	sk->fd = fd;
	return 0;
}

int gwhf_sock_set_nonblock(struct gwhf_sock *sk)
{
	u_long mode = 1;
	int ret;

	ret = ioctlsocket(sk->fd, FIONBIO, &mode);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}

int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
		   socklen_t len)
{
	int ret;

	ret = bind(sk->fd, (struct sockaddr *)sg, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}

int gwhf_sock_listen(struct gwhf_sock *sk, int backlog)
{
	return listen(sk->fd, backlog);
}

int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
		     struct sockaddr_gwhf *sg, socklen_t *len)
{
	SOCKET fd;

	fd = accept(sk->fd, (struct sockaddr *)sg, len);
	if (fd == INVALID_SOCKET)
		return WSAGetLastError();

	ret->fd = fd;
	return 0;
}

int gwhf_sock_connect(struct gwhf_sock *sk, struct sockaddr_gwhf *dst,
		      socklen_t len)
{
	int ret;

	ret = connect(sk->fd, (struct sockaddr *)dst, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}

int gwhf_sock_close(struct gwhf_sock *sk)
{
	int ret;

	if (sk->fd == INVALID_SOCKET)
		return 0;

	ret = closesocket(sk->fd);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	sk->fd = INVALID_SOCKET;
	return 0;
}

int gwhf_sock_recv(struct gwhf_sock *sk, void *buf, size_t len, int flags)
{
	int ret;

	ret = recv(sk->fd, buf, len, flags);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return ret;
}

int gwhf_sock_send(struct gwhf_sock *sk, const void *buf, size_t len,
		   int flags)
{
	int ret;

	ret = send(sk->fd, buf, len, flags);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return ret;
}

int gwhf_sock_getname(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
		      socklen_t *len)
{
	int ret;

	ret = getsockname(sk->fd, (struct sockaddr *)sg, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}

int gwhf_sock_getpeername(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
			  socklen_t *len)
{
	int ret;

	ret = getpeername(sk->fd, (struct sockaddr *)sg, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

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
