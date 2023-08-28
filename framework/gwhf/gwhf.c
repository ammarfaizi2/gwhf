// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./internal.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

static int run_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	switch (arg->ev_type) {
	case GWHF_EV_EPOLL:
		return gwhf_ev_epoll_run(wrk);
	default:
		return -EINVAL;
	}
}

static void *run_worker(void *arg)
{
	struct gwhf_worker *wrk = arg;
	return GWHF_ERR_PTR(run_ev(wrk));
}

static int init_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	switch (arg->ev_type) {
	case GWHF_EV_EPOLL:
		return gwhf_ev_epoll_init(wrk);
	default:
		return -EINVAL;
	}
}

static void destroy_ev(struct gwhf_worker *wrk)
{
	struct gwhf_init_arg *arg = &wrk->ctx->init_arg;

	wrk->ctx->stop = true;

	switch (arg->ev_type) {
	case GWHF_EV_EPOLL:
		gwhf_ev_epoll_destroy(wrk);
		break;
	default:
		break;
	}
}

static int init_worker(struct gwhf_worker *wrk)
{
	uint32_t max_clients = wrk->ctx->init_arg.max_clients;
	int ret;

	ret = mutex_init(&wrk->mutex);
	if (ret)
		return ret;

	ret = cond_init(&wrk->cond);
	if (ret)
		goto out_mutex;

	ret = gwhf_client_init_slot(&wrk->client_slot, max_clients);
	if (ret)
		goto out_cond;

	ret = init_ev(wrk);
	if (ret)
		goto out_client;

	/*
	 * Don't create a subthread for the main worker.
	 */
	if (wrk->id == 0)
		return 0;

	ret = thread_create(&wrk->thread, &run_worker, wrk);
	if (ret)
		goto out_ev;

	return 0;

out_ev:
	destroy_ev(wrk);
out_client:
	gwhf_client_destroy_slot(&wrk->client_slot);
out_cond:
	cond_destroy(&wrk->cond);
out_mutex:
	mutex_destroy(&wrk->mutex);
	return ret;	
}

static void destroy_worker(struct gwhf_worker *wrk)
{
	destroy_ev(wrk);
	gwhf_client_destroy_slot(&wrk->client_slot);
	cond_destroy(&wrk->cond);
	mutex_destroy(&wrk->mutex);

	/*
	 * Don't join the main worker thread. It doesn't have a subthread.
	 */
	if (wrk->id == 0)
		return;

	thread_join(wrk->thread, NULL);
}

static int init_workers(struct gwhf *ctx)
{
	uint32_t nr_workers = ctx->init_arg.nr_workers;
	struct gwhf_worker *workers;
	uint32_t i;
	int ret;

	workers = calloc(nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->internal->workers = workers;
	for (i = 0; i < nr_workers; i++) {
		workers[i].id = i;
		workers[i].ctx = ctx;
		ret = init_worker(&workers[i]);
		if (ret)
			goto out_err;
	}

	return 0;


out_err:
	while (i--)
		destroy_worker(&workers[i]);

	free(workers);
	ctx->internal->workers = NULL;
	return ret;
}

static void destroy_workers(struct gwhf *ctx)
{
	struct gwhf_worker *workers = ctx->internal->workers;
	uint32_t nr_workers = ctx->init_arg.nr_workers;
	uint32_t i;

	if (!workers)
		return;

	for (i = 0; i < nr_workers; i++)
		destroy_worker(&workers[i]);

	free(workers);
	ctx->internal->workers = NULL;
}

static int init_internal_state(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi;
	int ret;

	ctxi = calloc(1, sizeof(*ctxi));
	if (!ctxi)
		return -ENOMEM;

	ctx->internal = ctxi;

	ret = gwhf_signal_init_handler(ctx);
	if (ret)
		goto out_ctxi;

#ifdef CONFIG_HTTPS
	ret = gwhf_ssl_init(ctx);
	if (ret)
		goto out_signal;
#endif

	ret = init_socket(ctx);
	if (ret)
#ifdef CONFIG_HTTPS
		goto out_ssl;
#else
		goto out_signal;
#endif

	ret = init_workers(ctx);
	if (ret)
		goto out_socket;

	return 0;

out_socket:
	destroy_socket(ctx);
#ifdef CONFIG_HTTPS
out_ssl:
	gwhf_ssl_destroy(ctx);
#endif
out_signal:
	gwhf_signal_revert_sig_handler(ctx);
out_ctxi:
	ctx->internal = NULL;
	free(ctxi);
	return ret;
}

static void destroy_internal_state(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi;

	if (!ctx)
		return;

	ctxi = ctx->internal;
	if (!ctxi)
		return;

	destroy_workers(ctx);
	destroy_socket(ctx);
	gwhf_route_destroy(ctx);
#ifdef CONFIG_HTTPS
	gwhf_ssl_destroy(ctx);
#endif
	free(ctxi);
	memset(ctx, 0, sizeof(*ctx));
}

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

__cold __noinline
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
	int ret;

	ret = gwhf_route_init(ctx);
	if (ret)
		return ret;

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
