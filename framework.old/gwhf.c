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
#include <stdio.h>

/*
 * For signal handler only.
 */
static struct gwhf *g_gwhf;

static int validate_and_adjust_init_arg_ev(struct gwhf_init_arg *arg)
{
	switch (arg->ev_type) {
	case GWHF_EV_TYPE_DEFAULT:
		arg->ev_type = GWHF_EV_TYPE_EPOLL;
		__attribute__((__fallthrough__));
	case GWHF_EV_TYPE_EPOLL:
		return gwhf_validate_and_adjust_init_arg_ev_epoll(arg);
	case GWHF_EV_TYPE_SELECT:
	case GWHF_EV_TYPE_POLL:
	case GWHF_EV_TYPE_KQUEUE:
	case GWHF_EV_TYPE_IO_URING:
	default:
		return -EOPNOTSUPP;
	}
}

static int validate_and_adjust_init_arg(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	int ret;

	ret = validate_and_adjust_init_arg_ev(arg);
	if (ret)
		return ret;

	if (arg->nr_clients == 0)
		arg->nr_clients = 8192;

	if (!arg->bind_addr[0])
		memcpy(arg->bind_addr, "::", 3);

	if (!arg->bind_port)
		arg->bind_port = 8444;

	if (!arg->listen_backlog)
		arg->listen_backlog = 512;

	return 0;
}

static void gwhf_signal_handler(int sig)
{
	char c = '\n';

	if (!g_gwhf)
		return;

	if (g_gwhf->stop)
		return;

	g_gwhf->stop = true;
	if (write(STDERR_FILENO, &c, 1)) {
		/* Do nothing */
		(void)sig;
	}
}

static int init_signal_handler(struct gwhf *ctx)
{
	struct sigaction sa = { .sa_handler = gwhf_signal_handler };
	struct sigaction old;
	int err;

	g_gwhf = ctx;

	err = sigaction(SIGINT, &sa, &old);
	if (err < 0)
		return -errno;

	ctx->old_act[0] = old;
	err = sigaction(SIGTERM, &sa, &old);
	if (err < 0) {
		err = -errno;
		goto out_sigint;
	}

	ctx->old_act[1] = old;
	sa.sa_handler = SIG_IGN;
	err = sigaction(SIGPIPE, &sa, &old);
	if (err < 0) {
		err = -errno;
		goto out_sigterm;
	}

	ctx->old_act[2] = old;
	return 0;

out_sigterm:
	sigaction(SIGTERM, &ctx->old_act[1], NULL);
out_sigint:
	sigaction(SIGINT, &ctx->old_act[0], NULL);
	return err;
}

static void revert_signal_handler(struct gwhf *ctx)
{
	sigaction(SIGPIPE, &ctx->old_act[2], NULL);
	sigaction(SIGTERM, &ctx->old_act[1], NULL);
	sigaction(SIGINT, &ctx->old_act[0], NULL);
}

static int fill_sockaddr_ss(struct sockaddr_gwhf *sg, const char *addr,
			    uint16_t port)
{
	struct sockaddr_in6 *sin6 = (void *)sg;
	struct sockaddr_in *sin = (void *)sg;
	int err;

	memset(sg, 0, sizeof(*sg));

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

static inline socklen_t get_sockaddr_len(const struct sockaddr_gwhf *sg)
{
	switch (sg->sa.sa_family) {
	case AF_INET:
		return sizeof(sg->sin);
	case AF_INET6:
		return sizeof(sg->sin6);
	default:
		return 0;
	}
}

static int init_tcp_socket(struct gwhf *ctx)
{
	const int type = SOCK_STREAM | SOCK_NONBLOCK;
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct sockaddr_gwhf addr;
	int err;
#if defined(__linux__)
	int val;
#endif

	err = fill_sockaddr_ss(&addr, arg->bind_addr, arg->bind_port);
	if (err < 0)
		return err;

	err = gwhf_sock_create(&ctx->tcp, addr.sa.sa_family, type, 0);
	if (err < 0)
		return err;

#if defined(__linux__)
	val = 1;
	setsockopt(ctx->tcp.fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(ctx->tcp.fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#endif

	err = gwhf_sock_bind(&ctx->tcp, &addr, get_sockaddr_len(&addr));
	if (err < 0)
		goto out_err;

	err = gwhf_sock_listen(&ctx->tcp, arg->listen_backlog);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	gwhf_sock_close(&ctx->tcp);
	return err;
}

static void destroy_tcp_socket(struct gwhf *ctx)
{
	gwhf_sock_close(&ctx->tcp);
}

static int init_event_loop(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;

	switch (arg->ev_type) {
	case GWHF_EV_TYPE_DEFAULT:
		assert(0);
		return -EINVAL;
	case GWHF_EV_TYPE_EPOLL:
		return gwhf_init_ev_epoll(ctx);
	case GWHF_EV_TYPE_SELECT:
	case GWHF_EV_TYPE_POLL:
	case GWHF_EV_TYPE_KQUEUE:
	case GWHF_EV_TYPE_IO_URING:
	default:
		return -EOPNOTSUPP;
	}
}

static void destroy_event_loop(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;

	switch (arg->ev_type) {
	case GWHF_EV_TYPE_DEFAULT:
		assert(0);
		return;
	case GWHF_EV_TYPE_EPOLL:
		gwhf_destroy_ev_epoll(ctx);
		return;
	case GWHF_EV_TYPE_SELECT:
	case GWHF_EV_TYPE_POLL:
	case GWHF_EV_TYPE_KQUEUE:
	case GWHF_EV_TYPE_IO_URING:
	default:
		return;
	}
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

static void destroy_internal_data(struct gwhf *ctx)
{
	struct gwhf_internal *data = ctx->internal_data;

	gwhf_destroy_route_header(data);
	gwhf_destroy_route_body(data);
	free(data);
}

__cold noinline
void gwhf_destroy(struct gwhf *ctx)
{
	gwhf_destroy_client_slot(ctx);
	destroy_internal_data(ctx);
	destroy_event_loop(ctx);
	destroy_tcp_socket(ctx);
	revert_signal_handler(ctx);
	memset(ctx, 0, sizeof(*ctx));
}

__cold
int gwhf_init(struct gwhf *ctx)
{
	return gwhf_init_arg(ctx, NULL);
}

__cold noinline
int gwhf_init_arg(struct gwhf *ctx, const struct gwhf_init_arg *arg)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));

	if (arg)
		ctx->init_arg = *arg;

	ret = validate_and_adjust_init_arg(ctx);
	if (unlikely(ret))
		return ret;

	ret = init_signal_handler(ctx);
	if (unlikely(ret))
		return ret;

	ret = init_tcp_socket(ctx);
	if (unlikely(ret))
		return ret;

	ret = init_event_loop(ctx);
	if (ret < 0)
		goto out_err;

	ret = init_internal_data(ctx);
	if (ret < 0)
		goto out_err;

	ret = gwhf_init_client_slot(ctx);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	gwhf_destroy(ctx);
	return ret;
}

int gwhf_run(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;

	switch (arg->ev_type) {
	case GWHF_EV_TYPE_DEFAULT:
		return -EINVAL;
	case GWHF_EV_TYPE_EPOLL:
		return gwhf_run_ev_epoll(ctx);
	case GWHF_EV_TYPE_SELECT:
	case GWHF_EV_TYPE_POLL:
	case GWHF_EV_TYPE_KQUEUE:
	case GWHF_EV_TYPE_IO_URING:
	default:
		return -EOPNOTSUPP;
	}
}
