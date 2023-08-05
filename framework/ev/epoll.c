// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "epoll.h"

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static int epoll_add(int epfd, int fd, uint32_t events, union epoll_data data);

__cold
int gwhf_validate_and_adjust_init_arg_ev_epoll(struct gwhf_init_arg *arg)
{
	struct gwhf_init_arg_ev_epoll *epoll_arg = &arg->ev.epoll;

	if (epoll_arg->max_events == 0)
		epoll_arg->max_events = 512;

	if (epoll_arg->timeout <= 0)
		epoll_arg->timeout = -1;

	return 0;
}

__cold
int gwhf_init_ev_epoll(struct gwhf *ctx)
{
	struct gwhf_init_arg_ev_epoll *arg = &ctx->init_arg.ev.epoll;
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
	struct epoll_event *events = NULL;
	int ep_fd = -1, ev_fd = -1;
	union epoll_data data;
	int err;

	ep_fd = epoll_create(10000);
	if (ep_fd < 0) {
		err = -errno;
		goto out_err;
	}

	ev_fd = eventfd(0, EFD_NONBLOCK);
	if (ev_fd < 0) {
		err = -errno;
		goto out_err;
	}

	events = calloc(arg->max_events, sizeof(*events));
	if (!events) {
		err = -ENOMEM;
		goto out_err;
	}

	data.u64 = 0;
	err = epoll_add(ep_fd, ctx->tcp.fd, EPOLLIN, data);
	if (err)
		goto out_err;

	data.u64 = 1;
	err = epoll_add(ep_fd, ev_fd, EPOLLIN, data);
	if (err)
		goto out_err;

	ep->events = events;
	ep->epoll_fd = ep_fd;
	ep->event_fd = ev_fd;
	ep->timeout = arg->timeout;
	ep->max_events = arg->max_events;
	return 0;

out_err:
	if (ep_fd >= 0)
		close(ep_fd);
	if (ev_fd >= 0)
		close(ev_fd);
	free(events);
	return err;
}

__cold
void gwhf_destroy_ev_epoll(struct gwhf *ctx)
{
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;

	if (!ep->events)
		return;

	close(ep->epoll_fd);
	close(ep->event_fd);
	free(ep->events);
}

__hot
static int epoll_add(int epfd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
	if (unlikely(ret < 0))
		return -errno;

	return 0;
}

__hot
static int epoll_del(int epfd, int fd)
{
	int ret;

	ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (unlikely(ret < 0))
		return -errno;

	return 0;
}

__hot
static int epoll_mod(int epfd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
	if (unlikely(ret < 0))
		return -errno;

	return 0;
}

static int poll_events(struct gwhf *ctx)
{
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
	int ret;

	ret = epoll_wait(ep->epoll_fd, ep->events, ep->max_events, ep->timeout);
	if (unlikely(ret < 0)) {

		ret = -errno;
		if (ret == -EINTR)
			return 0;

		return ret;
	}

	return ret;
}

static int handle_too_many_files(struct gwhf *ctx)
{
	ctx->stop_accepting = true;
	return epoll_del(ctx->ev_epoll.epoll_fd, ctx->tcp.fd);
}

static int do_accept(struct gwhf *ctx, struct sockaddr *addr, socklen_t *len,
		     bool *got_client)
{
	int tcp_fd = ctx->tcp.fd;
	int ret;

	ret = accept4(tcp_fd, addr, len, SOCK_NONBLOCK);
	if (unlikely(ret < 0)) {

		ret = -errno;
		*got_client = false;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		if (ret == -ENFILE || ret == -EMFILE)
			return handle_too_many_files(ctx);

		return ret;
	}

	*got_client = true;
	return ret;
}

static int epoll_gwhf_put_client(struct gwhf *ctx, struct gwhf_client *cl)
{
	bool put_closes_fd = (cl->fd >= 0);

	gwhf_put_client(&ctx->client_slot, cl);
	if (put_closes_fd && ctx->stop_accepting) {
		int epl_fd = ctx->ev_epoll.epoll_fd;
		union epoll_data data;
		int err;

		data.u64 = 0;
		err = epoll_add(epl_fd, ctx->tcp.fd, EPOLLIN, data);
		if (err < 0) {
			ctx->stop = true;
			return err;
		}
		ctx->stop_accepting = false;
	}

	return 0;
}

static int assign_client_slot(struct gwhf *ctx, int fd,
			      const struct sockaddr_gwhf *addr)
{
	struct gwhf_client *cl;
	union epoll_data data;
	int err;

	cl = gwhf_get_client(&ctx->client_slot);
	if (unlikely(GWHF_IS_ERR(cl)))
		return GWHF_PTR_ERR(cl);

	data.ptr = cl;
	err = epoll_add(ctx->ev_epoll.epoll_fd, fd, EPOLLIN, data);
	if (unlikely(err < 0)) {
		epoll_gwhf_put_client(ctx, cl);
		return err;
	}

	cl->fd = fd;
	cl->addr = *addr;
	return 0;
}

static int handle_new_connection(struct gwhf *ctx)
{
	struct sockaddr_gwhf addr;
	uint32_t try_count = 0;
	bool got_client;
	socklen_t len;
	int fd, err;

repeat:
	try_count++;
	len = sizeof(addr);
	fd = do_accept(ctx, (struct sockaddr *)&addr, &len, &got_client);
	if (unlikely(fd < 0))
		return fd;

	if (!got_client)
		return 0;

	err = assign_client_slot(ctx, fd, &addr);
	if (unlikely(err < 0)) {
		close(fd);
		return err;
	}

	if (try_count < 128)
		goto repeat;

	return 0;
}

static int handle_event_fd(struct gwhf *ctx)
{
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
	uint64_t data;
	ssize_t ret;

	ret = read(ep->event_fd, &data, sizeof(data));
	if (unlikely(ret < 0))
		return -errno;

	return 0;
}

static inline struct epoll_event *cl_get_ev(struct gwhf_client *cl)
{
	return cl->private_data;
}

static int do_recv(struct gwhf_client *cl)
{
	ssize_t ret;
	size_t len;
	char *buf;

	ret = gwhf_get_recv_buffer(cl, (void **)&buf, &len);
	if (unlikely(ret < 0))
		return ret;

	assert(len > 0);
	ret = recv(cl->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0))
		return -errno;

	if (unlikely(ret == 0))
		return -ECONNRESET;

	gwhf_advance_recv_buffer(cl, (size_t)ret);
	return (int)ret;
}

static int handle_send_buf_after_recv(struct gwhf_client *cl)
{
	if (gwhf_client_has_pending_send(cl)) {
		struct epoll_event *ev = cl_get_ev(cl);
		ev->events |= EPOLLOUT;
	}

	return 0;
}

static int handle_client_recv(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	while (1) {
		ret = do_recv(cl);
		if (unlikely(ret < 0)) {
			if (ret == -EAGAIN)
				return 0;

			if (ret == -EINTR)
				continue;

			return ret;
		}

		ret = gwhf_consume_client_recv_buf(ctx, cl);
		if (ret < 0) {
			if (ret == -EAGAIN)
				continue;

			return ret;
		}

		return handle_send_buf_after_recv(cl);
	}

	return 0;
}

static int do_send(struct gwhf_client *cl)
{
	const void *buf;
	ssize_t ret;
	size_t len;

	ret = gwhf_get_send_buffer(cl, &buf, &len);
	if (unlikely(ret < 0))
		return ret;

	if (!len)
		return 0;

	ret = send(cl->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0))
		return -errno;

	if (unlikely(ret == 0))
		return -ECONNRESET;

	gwhf_advance_send_buffer(cl, (size_t)ret);
	return (int)ret;
}

static int handle_send_eagain(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
	uint32_t tmp = EPOLLIN | EPOLLOUT;
	union epoll_data data;

	if (cl->pollout_set)
		return 0;

	cl->pollout_set = true;
	data.ptr = cl;
	return epoll_mod(ep->epoll_fd, cl->fd, tmp, data);
}

static int handle_send_buffer_complete(struct gwhf *ctx, struct gwhf_client *cl)
{
	if (cl->pollout_set) {
		struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
		uint32_t tmp = EPOLLIN;
		union epoll_data data;

		cl->pollout_set = false;
		data.ptr = cl;
		return epoll_mod(ep->epoll_fd, cl->fd, tmp, data);
	}

	return 0;
}

static int handle_client_send(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	while (1) {
		ret = do_send(cl);
		if (unlikely(ret < 0)) {

			if (ret == -EAGAIN)
				return handle_send_eagain(ctx, cl);

			if (ret == -EINTR)
				continue;

			return ret;
		}

		if (!gwhf_client_has_pending_send(cl))
			return handle_send_buffer_complete(ctx, cl);
	}
}

static int handle_client(struct gwhf *ctx, struct epoll_event *ev)
{
	struct gwhf_client *cl = ev->data.ptr;
	int put = 0;
	int err = 0;

	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		put = 1;
		goto out;
	}

	cl->private_data = ev;
	cl->last_act = ctx->now;
	if (ev->events & EPOLLIN) {
		put = handle_client_recv(ctx, cl);
		if (put)
			goto out;
	}

	if (ev->events & EPOLLOUT) {
		put = handle_client_send(ctx, cl);
		if (put)
			goto out;
	}

out:
	cl->private_data = NULL;
	if (put) {
		err = epoll_del(ctx->ev_epoll.epoll_fd, cl->fd);
		epoll_gwhf_put_client(ctx, cl);
	}

	return err;
}

static int handle_event(struct gwhf *ctx, struct epoll_event *ev)
{
	if (ev->data.u64 == 0)
		return handle_new_connection(ctx);

	if (ev->data.u64 == 1)
		return handle_event_fd(ctx);

	return handle_client(ctx, ev);
}

static int handle_events(struct gwhf *ctx, int nr_events)
{
	struct gwhf_ev_epoll *ep = &ctx->ev_epoll;
	int ret = 0, i;

	for (i = 0; i < nr_events; i++) {
		ret = handle_event(ctx, &ep->events[i]);
		if (unlikely(ret < 0))
			break;
	}

	return ret;
}

__hot
int gwhf_run_ev_epoll(struct gwhf *ctx)
{
	int ret = 0;

	while (!ctx->stop) {
		ret = poll_events(ctx);
		if (unlikely(ret < 0))
			break;

		ret = handle_events(ctx, ret);
		if (unlikely(ret < 0))
			break;
	}

	ctx->stop = true;
	return ret;
}
