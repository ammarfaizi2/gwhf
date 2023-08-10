// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhf/gwhf.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "event/epoll.h"

static int validate_init_arg(struct gwhf_init_arg *arg)
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

	/*
	 * Currently, only epoll is supported.
	 */
	if (arg->ev_type != GWHF_EV_EPOLL)
		return -EINVAL;

	ret = validate_init_arg_ev_epoll(&arg->ev_epoll);
	if (ret)
		return ret;

	return 0;
}

static int gwhf_init_socket(struct gwhf *ctx)
{
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_sock *tcp = &ctxi->tcp;
	struct sockaddr_gwhf addr;
	int ret;

	ret = gwhf_sock_fill_addr(&addr, arg->bind_addr, arg->bind_port);
	if (ret)
		return ret;

	ret = gwhf_sock_create(tcp, addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (ret)
		goto out_err;

	ret = gwhf_sock_set_nonblock(tcp);
	if (ret)
		goto out_err;

	ret = gwhf_sock_bind(tcp, &addr, gwhf_sock_addr_len(&addr));
	if (ret)
		goto out_err;

	ret = gwhf_sock_listen(tcp, arg->backlog);
	if (ret)
		goto out_err;

	return 0;

out_err:
	gwhf_sock_close(tcp);
	return ret;
}

static void gwhf_destroy_socket(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	gwhf_sock_close(&ctxi->tcp);
}

static void *gwhf_run_worker(void *arg)
{
	struct gwhf_worker *wrk = arg;
	struct gwhf *ctx = wrk->ctx;

	thread_setname(wrk->thread, "gwhf-wrk-%u", wrk->id);
	return NULL;
}

static int gwhf_init_worker(struct gwhf *ctx, struct gwhf_worker *wrk)
{
	int ret;

	wrk->ctx = ctx;
	/*
	 * If @wrk->id, do not create a thread. It will run on the
	 * main thread later.
	 */
	if (wrk->id > 0) {
		ret = thread_create(&wrk->thread, gwhf_run_worker, wrk);
		if (ret)
			return ret;
	}

	return 0;
}

static void gwhf_destroy_worker(struct gwhf_worker *wrk)
{
	if (wrk->id > 0) {
		wrk->ctx->stop = true;
		thread_join(wrk->thread, NULL);
	}
}

static int gwhf_init_workers(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_worker *workers;
	uint32_t i;
	int ret;

	ctxi->nr_workers = ctx->init_arg.nr_workers;
	workers = calloc(ctxi->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	for (i = 0; i < ctxi->nr_workers; i++) {
		workers[i].id = i;
		ret = gwhf_init_worker(ctx, &workers[i]);
		if (ret) {
			while (i--)
				gwhf_destroy_worker(&workers[i]);

			free(workers);
			return ret;
		}
	}

	ctxi->workers = workers;
	return 0;
}

static void gwhf_destroy_workers(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	struct gwhf_worker *workers = ctxi->workers;
	uint32_t i;

	if (!workers)
		return;

	for (i = 0; i < ctxi->nr_workers; i++)
		gwhf_destroy_worker(&workers[i]);

	free(workers);
	ctxi->workers = NULL;
}

static int gwhf_init_internal_state(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi;
	int ret;

	ctxi = calloc(1, sizeof(*ctxi));
	if (!ctxi)
		return -ENOMEM;

	ctx->internal = ctxi;

	ret = gwhf_init_socket(ctx);
	if (ret)
		return ret;

	ret = gwhf_init_workers(ctx);
	if (ret)
		goto out_socket;

	return ret;

out_socket:
	gwhf_destroy_socket(ctx);
	free(ctxi);
	ctx->internal = NULL;
	return ret;
}

__cold
int gwhf_init(struct gwhf *ctx)
{
	return gwhf_init_arg(ctx, NULL);
}

__cold
int gwhf_init_arg(struct gwhf *ctx, struct gwhf_init_arg *arg)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	if (arg)
		ctx->init_arg = *arg;

	ret = validate_init_arg(&ctx->init_arg);
	if (ret)
		return ret;

	ret = gwhf_sock_global_init();
	if (ret)
		return ret;

	ret = gwhf_init_internal_state(ctx);
	if (ret)
		goto out_sock;

	return 0;

out_sock:
	gwhf_sock_global_destroy();
	return ret;
}

int gwhf_run(struct gwhf *ctx)
{
	return 0;
}

__cold
void gwhf_destroy(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	if (!ctxi)
		return;

	gwhf_destroy_workers(ctx);
	gwhf_destroy_socket(ctx);
	gwhf_sock_global_destroy();
	free(ctxi);
	memset(ctx, 0, sizeof(*ctx));
}

__cold
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
