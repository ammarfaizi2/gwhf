// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./internal.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

__cold
int gwhf_global_init(void)
{
	return gwhf_sock_global_init();
}

__cold
void gwhf_global_destroy(void)
{
	gwhf_sock_global_destroy();
}

__cold
int gwhf_init(struct gwhf *ctx)
{
	return gwhf_init_arg(ctx, NULL);
}

static int validate_and_adjust_arg(struct gwhf_init_arg *arg)
{
	int ret;

	if (!arg->bind_addr)
		arg->bind_addr = "::";

	if (!arg->bind_port)
		arg->bind_port = 60443;

	if (!arg->backlog)
		arg->backlog = 128;

	if (!arg->ev_type)
		arg->ev_type = GWHF_EV_EPOLL;

	if (!arg->nr_workers)
		arg->nr_workers = 4;

	if (!arg->max_clients)
		arg->max_clients = 8192;

	/*
	 * Currently, only epoll is supported.
	 */
	if (arg->ev_type != GWHF_EV_EPOLL)
		return -EINVAL;

	ret = gwhf_ev_epoll_validate_init_arg(&arg->ev_epoll);
	if (ret)
		return ret;

	return 0;
}

static int init_socket(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_internal *ctxi = ctx->internal;
	struct sockaddr_gwhf addr;
	struct gwhf_sock tcp;
	int ret;

	ret = gwhf_sock_fill_addr(&addr, arg->bind_addr, arg->bind_port);
	if (ret)
		return ret;

	ret = gwhf_sock_create(&tcp, addr.sa.sa_family, SOCK_STREAM, 0);
	if (ret)
		return ret;

	ret = gwhf_sock_set_nonblock(&tcp);
	if (ret)
		goto out_err;

	ret = gwhf_sock_bind(&tcp, &addr, gwhf_sock_addr_len(&addr));
	if (ret)
		goto out_err;

	ret = gwhf_sock_listen(&tcp, arg->backlog);
	if (ret)
		goto out_err;

	ctxi->tcp = tcp;
	return 0;

out_err:
	gwhf_sock_close(&tcp);
	return ret;
}

static void destroy_socket(struct gwhf *ctx)
{
	gwhf_sock_close(&ctx->internal->tcp);
}

static int init_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	if (arg->ev_type == GWHF_EV_EPOLL)
		return gwhf_ev_epoll_init_worker(wrk);

	return -EINVAL;
}

static void destroy_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	if (arg->ev_type == GWHF_EV_EPOLL)
		gwhf_ev_epoll_destroy_worker(wrk);
}

static int run_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	if (arg->ev_type == GWHF_EV_EPOLL)
		return gwhf_ev_epoll_run_worker(wrk);

	return -EINVAL;
}

static int __run_worker(struct gwhf_worker *wrk)
{
	return run_ev(wrk);
}

static void *run_worker(void *thread_arg)
{
	struct gwhf_worker *wrk = thread_arg;
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;
	int ret;

	ret = gwhf_client_init_slot(&wrk->client_slot, arg->max_clients);
	if (ret)
		goto out;

	ret = init_ev(wrk);
	if (ret)
		goto out_client_slot;

	ret = __run_worker(wrk);

	destroy_ev(wrk);
out_client_slot:
	gwhf_client_destroy_slot(&wrk->client_slot);
out:
	wrk->ctx->stop = true;
	return GWHF_ERR_PTR(ret);
}

static int spawn_worker(struct gwhf_worker *wrk)
{
	return thread_create(&wrk->thread, &run_worker, wrk);
}

static void stop_worker(struct gwhf_worker *wrk)
{
	wrk->ctx->stop = true;
	thread_join(wrk->thread, NULL);
}

static int init_workers(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_worker *workers;
	uint32_t i;
	int ret;

	if (!arg->nr_workers)
		arg->nr_workers = 2;

	workers = calloc(arg->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	for (i = 0; i < arg->nr_workers; i++) {
		workers[i].ctx = ctx;
		workers[i].id = i;

		if (i == 0)
			continue;

		ret = spawn_worker(&workers[i]);
		if (ret)
			goto out_err;
	}

	ctxi->workers = workers;
	ctxi->nr_workers = arg->nr_workers;
	return 0;

out_err:
	ctx->stop = true;
	while (i--)
		stop_worker(&workers[i]);

	free(workers);
	return ret;
}

static int init_internal_state(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi;
	int ret;

	ctxi = calloc(1, sizeof(*ctxi));
	if (!ctxi)
		return -ENOMEM;

	ctx->internal = ctxi;

	ret = init_socket(ctx);
	if (ret)
		goto out_ctxi;

	ret = init_workers(ctx);
	if (ret)
		goto out_socket;

	return 0;

out_socket:
	destroy_socket(ctx);
out_ctxi:
	free(ctxi);
	ctx->internal = NULL;
	return ret;
}

static void destroy_internal_state(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	destroy_socket(ctx);
	free(ctxi);
}

__cold noinline
int gwhf_init_arg(struct gwhf *ctx, const struct gwhf_init_arg *arg)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	if (arg)
		ctx->init_arg = *arg;

	ret = validate_and_adjust_arg(&ctx->init_arg);
	if (ret)
		return ret;

	return init_internal_state(ctx);
}

__cold
void gwhf_destroy(struct gwhf *ctx)
{
	destroy_internal_state(ctx);
	memset(ctx, 0, sizeof(*ctx));
}

int gwhf_run(struct gwhf *ctx)
{
	return GWHF_PTR_ERR(run_worker(&ctx->internal->workers[0]));
}

const char *gwhf_strerror(int err)
{
#ifdef _WIN32
	static __thread char __buf[8][256];
	static __thread uint8_t idx;

	char *buf = __buf[idx++ % 8];
	size_t len = sizeof(*__buf);

	strerror_s(buf, len, err);
	return buf;
#else
	return strerror(err);
#endif
}
