// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "../internal.h"
#include "epoll.h"

#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

static int poll_events(struct gwhf *ctx)
{
	struct gwhf_epoll *ep = &ctx->ep;
	int max_events = (int)ep->nr_events;
	int timeout = ep->timeout;
	int fd = ep->epoll_fd;
	int ret;

	ret = epoll_wait(fd, ep->events, max_events, timeout);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		return ret;
	}

	if (ret > 0)
		clock_gettime(CLOCK_BOOTTIME, &ctx->now);

	return ret;
}

static int do_accept(int fd, struct sockaddr_gwhf *addr, bool *got_client)
{
	socklen_t len = sizeof(*addr);
	int ret;

	ret = accept4(fd, (void *)addr, &len, SOCK_NONBLOCK);
	if (ret < 0) {
		*got_client = false;

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		return ret;
	}

	*got_client = true;
	return ret;
}

static int assign_conn_to_ctx(struct gwhf *ctx, int fd,
			      struct sockaddr_gwhf *addr)
{
	struct gwhf_client *cl;
	union epoll_data data;
	int err;

	cl = gwhf_get_client_slot(&ctx->client_slot);
	if (unlikely(cl == NULL))
		return -EAGAIN;

	data.ptr = cl;
	err = epoll_add(ctx->ep.epoll_fd, fd, EPOLLIN, data);
	if (unlikely(err < 0))
		return err;

	cl->fd = fd;
	cl->addr = *addr;
	cl->last_act = ctx->now;
	return 0;
}

static int handle_new_conn(struct gwhf *ctx)
{
	int err, fd, tcp_fd = ctx->socket.fd;
	struct sockaddr_gwhf addr;
	uint32_t try_count = 0;
	bool got;

try_again:
	got = false;
	fd = do_accept(tcp_fd, &addr, &got);
	if (unlikely(fd < 0))
		return fd;

	/*
	 * accept4() returns -EAGAIN?
	 */
	if (!got)
		return 0;

	err = assign_conn_to_ctx(ctx, fd, &addr);
	if (unlikely(err < 0)) {

		close(fd);
		if (err == -EAGAIN)
			err = 0;

		return err;
	}

	if (try_count++ < 128)
		goto try_again;

	return 0;
}

/*
 * This simply reads the eventfd. There is nothing interesting
 * other than waking up the epoll_wait() call.
 *
 * Consume the event just to get rid of EPOLLIN.
 */
static int handle_event_fd(struct gwhf *ctx)
{
	uint64_t data;
	ssize_t ret;

	ret = read(ctx->ep.event_fd, &data, sizeof(data));
	if (ret < 0)
		return -errno;

	return 0;
}

static inline struct epoll_event *get_epv_from_cl(struct gwhf_client *cl)
{
	return (struct epoll_event *)cl->private_data;
}

enum {
	RECV_GOT_DISCONNECTED = 1,
	SEND_GOT_DISCONNECTED = 1,
};

static int do_recv(struct gwhf_client *cl)
{
	uint16_t len;
	ssize_t ret;
	char *buf;

	buf = cl->req_buf + cl->req_buf_len;
	len = cl->req_buf_alloc - cl->req_buf_len - 1u;
	ret = recv(cl->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		return ret;
	}

	if (ret == 0)
		return -ECONNABORTED;

	cl->req_buf_len += (uint16_t)ret;
	return (int)ret;
}

static int handle_event_recv(struct gwhf *ctx, struct gwhf_client *cl)
{
	int ret;

	ret = do_recv(cl);
	if (unlikely(ret < 0))
		return ret;

	ret = gwhf_consume_recv_buffer(ctx, cl);
	if (ret < 0) {

		/*
		 * -EAGAIN means the request data has not been
		 * fully received yet. Just wait for the next
		 * EPOLLIN event.
		 */
		if (ret == -EAGAIN)
			return 0;

		return ret;
	}

	if (cl->state == T_CLST_SEND_HEADER || cl->state == T_CLST_SEND_BODY)
		get_epv_from_cl(cl)->events |= EPOLLOUT;

	return 0;
}

static int do_send(struct gwhf_client *cl, const void *buf, size_t len)
{
	ssize_t ret;

	ret = send(cl->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		return ret;
	}

	if (ret == 0)
		return -ECONNABORTED;

	return (int)ret;
}

static int handle_event_send(struct gwhf *ctx, struct gwhf_client *cl)
{
	const void *buf;
	size_t len;
	int ret;

	ret = gwhf_consume_send_buffer(cl, &buf, &len);
	if (unlikely(ret < 0))
		return ret;

	ret = do_send(cl, buf, len);
	if (unlikely(ret < 0))
		return ret;

	if (ret < (int)len) {
		if (!cl->pollout_set) {
			union epoll_data data;
			int ret;

			data.ptr = cl;
			ret = epoll_mod(ctx->ep.epoll_fd, cl->fd,
					EPOLLIN | EPOLLOUT, data);
			if (unlikely(ret < 0))
				return ret;

			cl->pollout_set = true;
		}
	}

	gwhf_send_buffer_advance(cl, (size_t)ret);
	return 0;
}

static int handle_event_client(struct gwhf *ctx, struct epoll_event *ev)
{
	struct gwhf_client *cl = ev->data.ptr;
	int put = 0;

	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		put = 1;
		goto out;
	}

	cl->last_act = ctx->now;
	cl->private_data = ev;

	if (ev->events & EPOLLIN) {
		put = handle_event_recv(ctx, cl);
		if (put)
			goto out;
	}

	if (ev->events & EPOLLOUT) {
		put = handle_event_send(ctx, cl);
		if (put)
			goto out;
	}

	cl->private_data = NULL;

out:
	if (put)
		gwhf_put_client_slot(&ctx->client_slot, cl);

	return 0;
}

static int handle_event(struct gwhf *ctx, struct epoll_event *ev)
{
	if (ev->data.u64 == 0)
		return handle_new_conn(ctx);

	if (ev->data.u64 == 1)
		return handle_event_fd(ctx);

	return handle_event_client(ctx, ev);
}

static int handle_events(struct gwhf *ctx, int nr_events)
{
	int i, ret = 0;

	for (i = 0; i < nr_events; i++) {
		ret = handle_event(ctx, &ctx->ep.events[i]);
		if (unlikely(ret < 0))
			break;
	}

	return ret;
}

__hot
int gwhf_run_event_loop_epoll(struct gwhf *ctx)
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

	return ret;
}

__hot
int epoll_add(int epfd, int fd, uint32_t events, union epoll_data data)
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
int epoll_del(int epfd, int fd)
{
	int ret;

	ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (unlikely(ret < 0))
		return -errno;

	return 0;
}

__hot
int epoll_mod(int epfd, int fd, uint32_t events, union epoll_data data)
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

__cold
int validate_and_adjust_ev_epoll_arg(struct gwhf_init_arg *arg)
{
	if (arg->epoll.max_events == 0)
		arg->epoll.max_events = 8192;

	if (arg->epoll.timeout == 0)
		arg->epoll.timeout = 6000;

	return 0;
}

__cold
void destroy_event_loop_epoll(struct gwhf_epoll *ep)
{
	if (ep->epoll_fd >= 0) {
		close(ep->epoll_fd);
		ep->epoll_fd = -1;
	}

	if (ep->event_fd >= 0) {
		close(ep->event_fd);
		ep->event_fd = -1;
	}

	if (ep->events) {
		free(ep->events);
		ep->events = NULL;
	}
}

__cold
int init_event_loop_epoll(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_epoll *ep = &ctx->ep;
	struct epoll_event *events = NULL;
	int err, epfd = -1, evfd = -1;
	union epoll_data data;

	epfd = epoll_create(20000);
	if (epfd < 0)
		return -errno;

	evfd = eventfd(0, EFD_NONBLOCK);
	if (evfd < 0) {
		err = -errno;
		goto out_err;
	}

	events = calloc(arg->epoll.max_events, sizeof(*events));
	if (events == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	data.u64 = 0;
	err = epoll_add(epfd, ctx->socket.fd, EPOLLIN, data);
	if (err < 0)
		goto out_err;

	data.u64 = 1;
	err = epoll_add(epfd, evfd, EPOLLIN, data);
	if (err < 0)
		goto out_err;

	ep->epoll_fd = epfd;
	ep->event_fd = evfd;
	ep->events = events;
	ep->nr_events = arg->epoll.max_events;
	ep->timeout = arg->epoll.timeout;
	return 0;

out_err:
	if (epfd >= 0)
		close(epfd);
	if (evfd >= 0)
		close(evfd);

	free(events);
	ep->epoll_fd = ep->event_fd = -1;
	return err;
}
