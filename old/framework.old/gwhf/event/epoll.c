// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
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
	socklen_t len;
	int err;

	err = gwhf_sock_fill_addr(&addr, "127.0.0.1", 0);
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

	len = gwhf_sock_addr_len(&addr);
	err = gwhf_sock_getname(&w, &addr, &len);
	if (err < 0)
		goto out_r;

	err = gwhf_sock_connect(&r, &addr, len);
	if (err < 0 && err != WSAEINPROGRESS)
		goto out_r;

	while (1) {
		err = gwhf_sock_accept(&tmp, &w, NULL, NULL);
		if (!err)
			break;
		if (err == WSAEWOULDBLOCK)
			continue;
		goto out_r;
	}

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
	int max_events = wrk->ctx->init_arg.ev_epoll.max_events;
	struct gwhf_internal *ctxi = wrk->ctx->internal;
	struct epoll_event *events;
	epoll_t epoll_fd;
	evfd_t event_fd;
	int err;

	events = calloc(max_events, sizeof(*events));
	if (!events)
		return -ENOMEM;

	epoll_fd = epoll_create(10000);
	if (epoll_fd < 0) {
		err = -ENOMEM;
		goto out_events;
	}

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

	wrk->events = events;
	wrk->epoll_fd = epoll_fd;
	wrk->event_fd = event_fd;
	return 0;

out_event_fd:
	close_event_fd(&event_fd);
out_epoll:
	epoll_close(epoll_fd);
out_events:
	free(events);
	return err;
}

int gwhf_destroy_worker_ev_epoll(struct gwhf_worker *wrk)
{
	struct gwhf_internal *ctxi = wrk->ctx->internal;

	signal_event_fd(&wrk->event_fd);
	if (wrk->id == 0)
		epoll_del(wrk->epoll_fd, &ctxi->tcp);
	close_event_fd(&wrk->event_fd);
	epoll_close(wrk->epoll_fd);
	return 0;
}

static int poll_events(struct gwhf_worker *wrk)
{
	struct gwhf *ctx = wrk->ctx;
	int max_events = ctx->init_arg.ev_epoll.max_events;
	int timeout = ctx->init_arg.ev_epoll.timeout;
	int ret;

	ret = epoll_wait(wrk->epoll_fd, wrk->events, max_events, timeout);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		return ret;
	}

	if (unlikely(ctx->stop))
		return 0;

	return ret;
}

static int handle_accept_err(struct gwhf_worker *wrk, int ret)
{
	if (ret == -EINTR)
		return 0;

	if (ret == -EAGAIN)
		return 0;

	if (ret == -EMFILE || ret == -ENFILE) {
		/*
		 * TODO(ammarfaizi2): This will result in a busy loop.
		 *                    Do something about it.
		 */
		return 0;
	}

	return ret;
}

static int assign_client(struct gwhf_worker *wrk, struct gwhf_client *cl,
			 struct gwhf_sock *fd, struct sockaddr_gwhf *addr)
{
	union epoll_data data;
	int ret;

	/*
	 * TODO(ammarfaizi2): Load balance this across workers.
	 */
	data.ptr = cl;
	ret = epoll_add(wrk->epoll_fd, fd, EPOLLIN, data);
	if (unlikely(ret < 0))
		return ret;

	cl->fd = *fd;
	cl->addr = *addr;
	return 0;
}

static int handle_event_new_client(struct gwhf_worker *wrk)
{
	struct gwhf_sock *tcp = &wrk->ctx->internal->tcp;
	struct sockaddr_gwhf addr;
	struct gwhf_client *cl;
	uint32_t try_count = 0;
	struct gwhf_sock fd;
	socklen_t len;
	int ret;

again:
	len = sizeof(addr);
	ret = gwhf_sock_accept(&fd, tcp, &addr, &len);
	if (ret < 0)
		return handle_accept_err(wrk, ret);

	if (unlikely((size_t)len > sizeof(addr))) {
		ret = -EINVAL;
		goto out_close;
	}

	ret = gwhf_sock_set_nonblock(&fd);
	if (unlikely(ret < 0))
		goto out_close;

	cl = gwhf_get_client(&wrk->client_slots);
	if (unlikely(GWHF_IS_ERR(cl))) {
		int err = GWHF_PTR_ERR(cl);
		if (err == -EAGAIN)
			ret = 0;
		else
			ret = err;

		goto out_close;
	}

	ret = assign_client(wrk, cl, &fd, &addr);
	if (unlikely(ret < 0)) {
		ret = 0;
		goto out_put;
	}

	if (try_count++ < 32)
		goto again;

	return 0;

out_put:
	gwhf_put_client(&wrk->client_slots, cl);
out_close:
	gwhf_sock_close(&fd);
	return ret;
}

static int handle_event_event_fd(struct gwhf_worker *wrk)
{
	return consume_event_fd(&wrk->event_fd);
}

static int handle_event_client_recv(struct gwhf_worker *wrk,
				    struct gwhf_client *cl)
{
	size_t len;
	void *buf;
	int ret;

	ret = gwhf_client_get_recv_buf(cl, &buf, &len);
	if (unlikely(ret < 0))
		return ret;

	ret = gwhf_sock_recv(&cl->fd, buf, len, 0);
	if (ret < 0)
		return ret;

	if (!ret)
		return -ECONNABORTED;

	return 0;
}

static int handle_event_client_send(struct gwhf_worker *wrk,
				    struct gwhf_client *cl)
{
	return 0;
}

static int handle_event_client(struct gwhf_worker *wrk, struct epoll_event *ev)
{
	struct gwhf_client *cl = ev->data.ptr;
	uint32_t events = ev->events;
	int put = 0;

	cl->data = ev;

	if (events & EPOLLIN) {
		put = handle_event_client_recv(wrk, cl);
		if (unlikely(put < 0))
			goto out;
	}

	if (events & EPOLLOUT) {
		put = handle_event_client_send(wrk, cl);
		if (unlikely(put < 0))
			goto out;
	}

out:
	cl->data = NULL;
	if (put)
		gwhf_put_client(&wrk->client_slots, cl);

	return 0;
}

static int handle_event(struct gwhf_worker *wrk, struct epoll_event *ev)
{
	struct gwhf *ctx = wrk->ctx;

	if (ev->data.u64 == 0)
		return handle_event_new_client(wrk);

	if (ev->data.u64 == 1)
		return handle_event_event_fd(wrk);

	return handle_event_client(wrk, ev);
}

static int handle_events(struct gwhf_worker *wrk, int nr_events)
{
	int i, ret = 0;

	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &wrk->events[i];

		ret = handle_event(wrk, ev);
		if (unlikely(ret < 0))
			break;
	}

	return ret;
}

int gwhf_run_worker_ev_epoll(struct gwhf_worker *wrk)
{
	struct gwhf *ctx = wrk->ctx;
	int ret = 0;

	while (!ctx->stop) {
		ret = poll_events(wrk);
		if (unlikely(ret < 0))
			break;

		ret = handle_events(wrk, ret);
		if (unlikely(ret < 0))
			break;
	}

	return ret;
}
