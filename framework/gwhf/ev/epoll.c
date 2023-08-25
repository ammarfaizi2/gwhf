// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#include "./epoll.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
	evt.data.u64 = 1;
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

static epoll_t gwhf_epoll_create(epoll_t *ep_fd, int size)
{
	int ret;

	ret = epoll_create(size);
	if (ret < 0)
		return -errno;

	*ep_fd = ret;
	return 0;
}
#elif defined(_WIN32) /* #if defined(__linux__) */
static int register_event_fd(epoll_t epfd, evfd_t *efd)
{
	struct epoll_event evt;
	int ret;

	evt.events = EPOLLIN;
	evt.data.u64 = 1;
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

static epoll_t gwhf_epoll_create(epoll_t *ep_fd, int size)
{
	*ep_fd = epoll_create(size);
	return 0;
}
#endif /* #if defined(__linux__) */

__cold
int gwhf_ev_epoll_validate_init_arg(struct gwhf_init_arg_ev_epoll *arg)
{
	if (!arg->timeout)
		arg->timeout = -1;

	if (!arg->max_events)
		arg->max_events = 8192;

	if (arg->max_events < 1)
		return -EINVAL;

	return 0;
}

__cold
int gwhf_ev_epoll_init_worker(struct gwhf_worker *wrk)
{
	int max_events = wrk->ctx->init_arg.ev_epoll.max_events;
	struct gwhf_internal *ctxi = wrk->ctx->internal;
	struct epoll_event *events;
	epoll_t ep_fd;
	evfd_t ev_fd;
	int err;

	if (max_events < 1)
		return -EINVAL;

	memset(&ev_fd, 0, sizeof(ev_fd));
	memset(&ep_fd, 0, sizeof(ep_fd));
	events = calloc(max_events, sizeof(*events));
	if (!events)
		return -ENOMEM;

	err = gwhf_epoll_create(&ep_fd, 10000);
	if (err)
		return err;

	err = create_event_fd(&ev_fd);
	if (err)
		goto out_ep_fd;

	err = register_event_fd(ep_fd, &ev_fd);
	if (err)
		goto out_ev_fd;

	if (wrk->id == 0) {
		/*
		 * Only the first worker will monitor the listening socket.
		 */
		union epoll_data data;

		data.u64 = 0;
		err = epoll_add(ep_fd, &ctxi->tcp, EPOLLIN, data);
		if (err)
			goto out_ev_fd;
	}

	wrk->ev.ep_fd = ep_fd;
	wrk->ev.ev_fd = ev_fd;
	wrk->ev.events = events;
	wrk->ev.max_events = max_events;
	return 0;

out_ev_fd:
	close_event_fd(&ev_fd);
out_ep_fd:
	epoll_close(ep_fd);
	return err;
}

__cold
void gwhf_ev_epoll_destroy_worker(struct gwhf_worker *wrk)
{
	struct gwhf_internal *ctxi = wrk->ctx->internal;

	signal_event_fd(&wrk->ev.ev_fd);
	if (wrk->id == 0)
		epoll_del(wrk->ev.ep_fd, &ctxi->tcp);
	close_event_fd(&wrk->ev.ep_fd);
	epoll_close(wrk->ev.ep_fd);
	free(wrk->ev.events);
}

static int poll_events(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg_ev_epoll *arg = &wrk->ctx->init_arg.ev_epoll;
	int max_events = arg->max_events;
	int timeout = arg->timeout;
	int ret;

	ret = epoll_wait(wrk->ev.ep_fd, wrk->ev.events, max_events, timeout);
	if (unlikely(ret < 0)) {
		ret = -errno;

		if (ret == -EINTR)
			return 0;

		return ret;
	}

	return ret;
}

static int assign_client_to_worker(struct gwhf_worker *wrk,
				   struct gwhf_client *cl,
				   struct gwhf_sock *sk,
				   struct sockaddr_gwhf *addr)
{
	union epoll_data data;
	int ret;

	data.ptr = cl;
	ret = epoll_add(wrk->ev.ep_fd, sk, EPOLLIN, data);
	if (ret < 0)
		return ret;

	cl->fd = *sk;
	cl->addr = *addr;
	cl->data = NULL;
	return 0;
}

static int handle_accept_error(struct gwhf_worker *wrk, int err)
{
	if (err == -EAGAIN || err == -EINTR)
		return 0;

	/*
	 * TODO(ammarfaizi2): Handle -ENFILE and -EMFILE.
	 */
	(void)wrk;

	return 0;
}

static int handle_new_connection(struct gwhf_worker *wrk)
{
	struct gwhf_sock *tcp = &wrk->ctx->internal->tcp;
	struct sockaddr_gwhf addr;
	struct gwhf_sock new_fd;
	struct gwhf_client *cl;
	socklen_t len;
	int ret;

	len = sizeof(addr);
	ret = gwhf_sock_accept(&new_fd, tcp, &addr, &len);
	if (ret < 0)
		return handle_accept_error(wrk, ret);

	cl = gwhf_client_get(&wrk->client_slot);
	if (GWHF_IS_ERR(cl)) {
		gwhf_sock_close(&new_fd);
		return 0;
	}

	ret = assign_client_to_worker(wrk, cl, &new_fd, &addr);
	if (ret < 0) {
		gwhf_client_put(&wrk->client_slot, cl);
		gwhf_sock_close(&new_fd);
		return 0;
	}

	return 0;
}

static int handle_event_fd(struct gwhf_worker *wrk)
{
	return consume_event_fd(&wrk->ev.ev_fd);
}

static int handle_event_client_recv(struct gwhf_worker *wrk,
				    struct gwhf_client *cl)
{
	uint32_t loop_count = 0;
	int ret;

	(void)wrk;

	while (1) {
		size_t len = 0;
		void *buf;

		ret = gwhf_client_get_recv_buf(cl, &buf, &len);
		if (ret < 0)
			break;

		ret = gwhf_sock_recv(&cl->fd, buf, len, 0);
		if (ret < 0)
			break;

		if (!ret) {
			ret = -ECONNRESET;
			break;
		}

		gwhf_client_advance_recv_buf(cl, (size_t)ret);
		ret = gwhf_client_consume_recv_buf(cl);
		if (ret != -EAGAIN)
			break;

		if (loop_count++ > 16)
			break;
	}

	if (ret == -EAGAIN || ret == -EINTR)
		ret = 0;

	return ret;
}

static int toggle_pollout(struct gwhf_worker *wrk, struct gwhf_client *cl,
			  bool set)
{
	union epoll_data data;
	uint32_t events;
	int ret;

	if (set == cl->pollout_set)
		return 0;

	data.ptr = cl;
	events = EPOLLIN | (set ? EPOLLOUT : 0);
	ret = epoll_mod(wrk->ev.ep_fd, &cl->fd, events, data);
	if (ret < 0)
		return ret;

	cl->pollout_set = set;
	return 0;
}

static int handle_event_client_send(struct gwhf_worker *wrk,
				    struct gwhf_client *cl)
{
	uint32_t loop_count = 0;
	int ret;

	while (1) {
		const void *buf;
		size_t len = 0;

		ret = gwhf_client_get_send_buf(cl, &buf, &len);
		if (ret < 0)
			break;

		if (!len)
			break;

		ret = gwhf_sock_send(&cl->fd, buf, len, 0);
		if (ret < 0)
			break;

		gwhf_client_advance_send_buf(cl, (size_t)ret);
		if (loop_count++ > 16) {
			ret = -EAGAIN;
			break;
		}
	}

	if (ret == -EAGAIN || ret == -EINTR)
		ret = toggle_pollout(wrk, cl, true);
	else if (ret == 0)
		ret = toggle_pollout(wrk, cl, false);

	return ret;
}

static void del_client_from_worker(struct gwhf_worker *wrk,
				   struct gwhf_client *cl)
{
	epoll_del(wrk->ev.ep_fd, &cl->fd);
}

static int handle_event_client(struct gwhf_worker *wrk, struct epoll_event *ev)
{
	struct gwhf_client *cl = ev->data.ptr;
	int put = 0;

	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		put = 1;
		goto out;
	}

	cl->data = ev;

	if (ev->events & EPOLLIN) {
		put = handle_event_client_recv(wrk, cl);
		if (put)
			goto out;
	}

	if (ev->events & EPOLLOUT) {
		put = handle_event_client_send(wrk, cl);
		if (put)
			goto out;
	}

out:
	cl->data = NULL;
	if (put) {
		del_client_from_worker(wrk, cl);
		gwhf_client_put(&wrk->client_slot, cl);
	}

	return 0;
}

static int handle_event(struct gwhf_worker *wrk, struct epoll_event *ev)
{
	if (ev->data.u64 == 0)
		return handle_new_connection(wrk);

	if (ev->data.u64 == 1)
		return handle_event_fd(wrk);

	return handle_event_client(wrk, ev);
}

static int handle_events(struct gwhf_worker *wrk, int nr_events)
{
	struct epoll_event *events = wrk->ev.events;
	int ret, i;

	for (i = 0; i < nr_events; i++) {
		ret = handle_event(wrk, &events[i]);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int gwhf_ev_epoll_run_worker(struct gwhf_worker *wrk)
{
	struct gwhf *ctx = wrk->ctx;
	int ret = 0;

	while (!ctx->stop) {
		ret = poll_events(wrk);
		if (ret < 0)
			break;

		ret = handle_events(wrk, ret);
		if (ret < 0)
			break;
	}

	return ret;
}
