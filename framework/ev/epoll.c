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

		return ret;
	}

	*got_client = true;
	return ret;
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
		gwhf_put_client(&ctx->client_slot, cl);
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

static int handle_event(struct gwhf *ctx, struct epoll_event *ev)
{
	if (ev->data.u64 == 0)
		return handle_new_connection(ctx);

	if (ev->data.u64 == 1)
		return handle_event_fd(ctx);

	return 0;
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
