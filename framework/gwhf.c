// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"
#include "ev/epoll.h"
#include "http/request.h"
#include "http/response.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>

__hot
struct gwhf_client *gwhf_get_client_slot(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t id;
	int ret;

	ret = gwhf_stack16_pop(&cs->stack, &id);
	if (unlikely(ret < 0))
		return NULL;

	cl = &cs->clients[id];
	assert(cl->id == id);
	assert(cl->fd < 0);

	ret = gwhf_init_client_req_buf(cl);
	if (unlikely(ret)) {
		gwhf_put_client_slot(cs, cl);
		return NULL;
	}

	assert(cl->state == T_CLST_CLOSED);
	cl->state = T_CLST_IDLE;
	return cl;
}

/*
 * Called when the gwhf_client is still used. Typically when
 * the connection is still open. One example is when the server
 * and client agree with "Connection: keep-alive".
 */
__hot
void gwhf_soft_reset_client(struct gwhf_client *cl)
{
	/*
	 * This tends to be called when the connection is still
	 * open after recv() and send(). So it must have the
	 * buffer not NULL.
	 */
	assert(cl->req_buf);
	assert(cl->res_buf);
	assert(cl->req_buf_alloc);
	assert(cl->res_buf_alloc);

	/*
	 * Do not free the buffer, just reset the length and number
	 * of bytes sent.
	 */
	cl->req_buf_len = 0;
	cl->res_buf_len = 0;
	cl->res_buf_sent = 0;

	gwhf_destroy_req_hdr(&cl->req_hdr);
	gwhf_destroy_res_hdr(&cl->res_hdr);
	gwhf_destroy_res_body(&cl->res_body);
	cl->total_req_body_recv = 0;

	assert(cl->state != T_CLST_IDLE);
	assert(cl->state != T_CLST_CLOSED);
	cl->state = T_CLST_IDLE;
}

__hot
void gwhf_reset_client(struct gwhf_client *cl)
{
	assert(cl->state != T_CLST_CLOSED);

	if (cl->fd >= 0) {
		close(cl->fd);
		cl->fd = -1;
	}

	gwhf_destroy_client_req_buf(cl);
	gwhf_destroy_client_res_buf(cl);
	gwhf_destroy_req_hdr(&cl->req_hdr);
	gwhf_destroy_res_hdr(&cl->res_hdr);
	gwhf_destroy_res_body(&cl->res_body);
	cl->total_req_body_recv = 0;
	cl->state = T_CLST_CLOSED;
}

__hot
void gwhf_put_client_slot(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	int ret;

	gwhf_reset_client(cl);
	ret = gwhf_stack16_push(&cs->stack, cl->id);
	if (unlikely(ret < 0)) {
		/*
		 * Must not happen.
		 */
		abort();
	}
}

static int validate_and_adjust_init_arg(struct gwhf_init_arg *arg)
{
	int ret = 0;

	if (arg->bind_addr == NULL)
		arg->bind_addr = "::";

	if (arg->bind_port == 0)
		arg->bind_port = 8444;

	if (arg->listen_backlog == 0)
		arg->listen_backlog = 1024;

	switch (arg->ev_type) {
	case GWHF_EV_DEFAULT:
		arg->ev_type = GWHF_EV_EPOLL;
		ret = validate_and_adjust_ev_epoll_arg(arg);
		break;
	case GWHF_EV_EPOLL:
		break;
	case GWHF_EV_POLL:
	case GWHF_EV_IO_URING:
		return -EOPNOTSUPP;
	}

	if (ret)
		return ret;

	if (arg->nr_clients == 0)
		arg->nr_clients = 10240;

	return 0;
}

static volatile bool *gwhf_stop_p;

static void gwhf_signal_handler(int sig)
{
	char p = '\n';

	if (!gwhf_stop_p)
		return;

	if (*gwhf_stop_p)
		return;

	*gwhf_stop_p = true;
	if (write(STDERR_FILENO, &p, 1) < 0) {
		/*
		 * Do nothing.
		 */
	}
	(void) sig;
}

static int init_signal_handler(void)
{
	struct sigaction act = { .sa_handler = gwhf_signal_handler };
	int ret;

	ret = sigaction(SIGINT, &act, NULL);
	if (ret)
		goto err;
	ret = sigaction(SIGTERM, &act, NULL);
	if (ret)
		goto err;

	act.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &act, NULL);
	if (ret)
		goto err;

	return 0;

err:
	return -errno;
}

static int fill_sockaddr_ss(struct sockaddr_storage *ss, const char *addr,
			    uint16_t port)
{
	struct sockaddr_in6 *sin6 = (void *)ss;
	struct sockaddr_in *sin = (void *)ss;
	int err;

	memset(ss, 0, sizeof(*ss));

	err = inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	if (err == 1) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		return 0;
	}

	err = inet_pton(AF_INET, addr, &sin->sin_addr);
	if (err == 1) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		return 0;
	}

	return -EINVAL;
}

static socklen_t get_sockaddr_len(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;
	}
}

static void destroy_socket(struct gwhf *ctx)
{
	struct gwhf_socket *sk = &ctx->socket;

	if (sk->fd >= 0) {
		close(sk->fd);
		sk->fd = -1;
	}
}

static int init_socket(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct sockaddr_storage ss;
	int fd, err, val;

	err = fill_sockaddr_ss(&ss, arg->bind_addr, arg->bind_port);
	if (err < 0)
		return err;

	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -errno;

	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	err = bind(fd, (void *)&ss, get_sockaddr_len(&ss));
	if (err < 0) {
		err = -errno;
		goto out_err;
	}

	err = listen(fd, arg->listen_backlog);
	if (err < 0) {
		err = -errno;
		goto out_err;
	}

	ctx->socket.fd = fd;
	return 0;

out_err:
	close(fd);
	ctx->socket.fd = -1;
	return err;
}

static void destroy_event_loop(struct gwhf *ctx)
{
	switch (ctx->init_arg.ev_type) {
	case GWHF_EV_EPOLL:
		return destroy_event_loop_epoll(&ctx->ep);
	}
}

static int init_event_loop(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	int ret = 0;

	switch (arg->ev_type) {
	case GWHF_EV_EPOLL:
		ret = init_event_loop_epoll(ctx);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return ret;
}

static void destroy_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	struct gwhf_client *cl, *clients = cs->clients;
	uint16_t i;

	if (!clients)
		return;

	for (i = 0; i < cs->stack.size; i++) {
		cl = &clients[i];
		if (cl->state != T_CLST_CLOSED)
			gwhf_reset_client(cl);
	}

	free(clients);
	cs->clients = NULL;
	gwhf_stack16_destroy(&cs->stack);
	memset(cs, 0, sizeof(*cs));
}

static void init_client(struct gwhf_client *cl)
{
	cl->fd = -1;
	gwhf_destroy_client_req_buf(cl);
	gwhf_destroy_client_res_buf(cl);
	gwhf_destroy_req_hdr(&cl->req_hdr);
	gwhf_destroy_res_hdr(&cl->res_hdr);
}

static int init_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cl = &ctx->client_slot;
	uint16_t nr_clients = ctx->init_arg.nr_clients;
	struct gwhf_client *clients;
	uint16_t i;
	int err;

	clients = calloc(nr_clients, sizeof(*clients));
	if (clients == NULL)
		return -ENOMEM;

	err = gwhf_stack16_init(&cl->stack, nr_clients);
	if (err < 0) {
		free(clients);
		return err;
	}

	i = nr_clients;
	while (i--) {
		init_client(&clients[i]);
		clients[i].id = i;
		err = __gwhf_stack16_push(&cl->stack, i);
		assert(err == 0);
	}

	cl->clients = clients;
	return 0;
}

static void destroy_internal_data(struct gwhf *ctx)
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);

	gwhf_destroy_route_header(it);
	gwhf_destroy_route_body(it);
	free(it);
}

static int init_internal_data(struct gwhf *ctx)
{
	struct gwhf_internal *data;

	data = calloc(1, sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	ctx->internal_data = data;
	return 0;
}

__cold
void gwhf_destroy(struct gwhf *ctx)
{
	destroy_client_slot(ctx);
	destroy_event_loop(ctx);
	destroy_socket(ctx);
	destroy_internal_data(ctx);
}

__cold
int gwhf_init(struct gwhf *ctx, const struct gwhf_init_arg *arg)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));

	if (arg)
		ctx->init_arg = *arg;

	ret = validate_and_adjust_init_arg(&ctx->init_arg);
	if (ret < 0)
		return ret;

	gwhf_stop_p = &ctx->stop;
	ret = init_signal_handler();
	if (ret < 0)
		return ret;

	ret = init_internal_data(ctx);
	if (ret < 0)
		return ret;

	ret = init_socket(ctx);
	if (ret < 0)
		goto out_err;

	ret = init_event_loop(ctx);
	if (ret < 0)
		goto out_err;

	ret = init_client_slot(ctx);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	gwhf_destroy(ctx);
	return ret;
}

int gwhf_run_event_loop(struct gwhf *ctx)
{
	switch (ctx->init_arg.ev_type) {
	case GWHF_EV_EPOLL:
		return gwhf_run_event_loop_epoll(ctx);
	default:
		return -EOPNOTSUPP;
	}
}
