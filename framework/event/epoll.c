// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhf/gwhf.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "epoll.h"

int validate_init_arg_ev_epoll(struct gwhf_init_arg_ev_epoll *arg)
{
	if (!arg->timeout)
		arg->timeout = -1;

	if (!arg->max_events)
		arg->max_events = 8192;

	if (arg->max_events < 1)
		return -EINVAL;

	return 0;
}

static int epoll_add(epoll_t epfd, struct gwhf_sock *sk, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sk->fd, &ev) < 0)
		return -1;

	return 0;
}

static int epoll_mod(epoll_t epfd, struct gwhf_sock *sk, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data
	};

	if (epoll_ctl(epfd, EPOLL_CTL_MOD, sk->fd, &ev) < 0)
		return -1;

	return 0;
}

static int epoll_del(epoll_t epfd, struct gwhf_sock *sk)
{
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, sk->fd, NULL) < 0)
		return -1;

	return 0;
}

#if defined(__linux__)
static int register_event_fd(epoll_t epfd, evfd_t *efd)
{
	struct epoll_event evt;
	int ret;

	evt.events = EPOLLIN;
	evt.data.u64 = 2;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, *efd, &evt);
	if (ret < 0)
		return -errno;

	return 0;
}

static int signal_event_fd(evfd_t *efd)
{
	uint64_t u = 1;
	int ret;

	ret = write(*efd, &u, sizeof(u));
	if (ret < 0)
		return -errno;

	return 0;
}

static int consume_event_fd(evfd_t *efd)
{
	uint64_t u;
	int ret;

	ret = read(*efd, &u, sizeof(u));
	if (ret < 0)
		return -errno;

	return 0;
}

static int create_event_fd(evfd_t *efd)
{
	int fd;

	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0)
		return -errno;

	*efd = fd;
	return 0;
}

static int close_event_fd(evfd_t *efd)
{
	return close(*efd);
}
#elif defined(_WIN32) /* #if defined(__linux__) */
static int register_event_fd(epoll_t epfd, evfd_t *efd)
{
	struct epoll_event evt;
	int ret;

	evt.events = EPOLLIN;
	evt.data.u64 = 2;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, efd->read.fd, &evt);
	if (ret < 0)
		return -errno;

	return 0;
}

static int signal_event_fd(evfd_t *efd)
{
	uint64_t u = 1;
	int ret;

	ret = gwhf_sock_send(&efd->write, &u, sizeof(u), 0);
	if (ret < 0)
		return ret;

	return 0;
}

static int consume_event_fd(evfd_t *efd)
{
	uint64_t u;
	int ret;

	ret = gwhf_sock_recv(&efd->read, &u, sizeof(u), 0);
	if (ret < 0)
		return ret;

	return 0;
}

static int create_event_fd(evfd_t *efd)
{
	struct gwhf_sock w, r, tmp;
	struct sockaddr_gwhf addr;
	int err;

	err = gwhf_sock_fill_addr(&addr, "127.0.0.1", 63121);
	if (err < 0)
		return err;

	err = gwhf_sock_create(&w, AF_INET, SOCK_STREAM, 0);
	if (err < 0)
		return err;

	err = gwhf_sock_set_nonblock(&w);
	if (err < 0)
		goto out_w;

	err = gwhf_sock_create(&r, AF_INET, SOCK_STREAM, 0);
	if (err < 0)
		goto out_w;

	err = gwhf_sock_set_nonblock(&r);
	if (err < 0)
		goto out_r;

	err = gwhf_sock_bind(&w, &addr, gwhf_sock_addr_len(&addr));
	if (err < 0)
		goto out_r;

	err = gwhf_sock_listen(&w, 1);
	if (err < 0)
		goto out_r;

	err = gwhf_sock_connect(&r, &addr, gwhf_sock_addr_len(&addr));
	if (err < 0)
		goto out_r;

	err = gwhf_sock_accept(&tmp, &w, NULL, NULL);
	if (err < 0)
		goto out_r;

	gwhf_sock_close(&w);
	efd->read = r;
	efd->write = tmp;
	return 0;

out_r:
	gwhf_sock_close(&r);
out_w:
	gwhf_sock_close(&w);
	return err;
}

static int close_event_fd(evfd_t *efd)
{
	gwhf_sock_close(&efd->read);
	gwhf_sock_close(&efd->write);
	return 0;
}
#endif /* #elif defined(_WIN32) */

int gwhf_init_worker_ev_epoll(struct gwhf_worker *wrk)
{
	struct gwhf_internal *ctxi = wrk->ctx->internal;
	epoll_t epoll_fd;
	evfd_t event_fd;
	int err;

	epoll_fd = epoll_create(10000);
	if (epoll_fd < 0)
		return -ENOMEM;

	memset(&event_fd, 0, sizeof(event_fd));
	err = create_event_fd(&event_fd);
	if (err)
		goto out_epoll;

	err = register_event_fd(epoll_fd, &event_fd);
	if (err)
		goto out_event_fd;

	if (wrk->id == 0) {
		union epoll_data data;

		data.u64 = 0;
		err = epoll_add(epoll_fd, &ctxi->tcp, EPOLLIN, data);
		if (err)
			goto out_event_fd;
	}

	wrk->epoll_fd = epoll_fd;
	wrk->event_fd = event_fd;
	return 0;

out_event_fd:
	close_event_fd(&event_fd);
out_epoll:
	epoll_close(epoll_fd);
	return err;
}

int gwhf_destroy_worker_ev_epoll(struct gwhf_worker *wrk)
{
	struct gwhf_internal *ctxi = wrk->ctx->internal;

	epoll_del(wrk->epoll_fd, &ctxi->tcp);
	close_event_fd(&wrk->event_fd);
	epoll_close(wrk->epoll_fd);
	return 0;
}

int gwhf_run_worker_ev_epoll(struct gwhf_worker *wrk)
{
	return 0;
}
