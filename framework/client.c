// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"
#include "ev/epoll.h"
#include "http/request.h"
#include "http/response.h"

static void init_client_first(struct gwhf_client *cl)
{
	cl->fd = -1;
}

__cold
int init_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	struct gwhf_init_arg *arg = &ctx->init_arg;
	struct gwhf_client *cl, *clients;
	uint16_t i;
	int err;

	clients = calloc(arg->nr_clients, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	err = gwhf_init_stack16(&cs->stack, arg->nr_clients);
	if (err) {
		free(clients);
		return err;
	}

	i = arg->nr_clients;
	while (i--) {
		cl = &clients[i];
		init_client_first(cl);
		err = __gwhf_push_stack16(&cs->stack, i);
		assert(err == 0);
		(void)err;
	}

	cs->clients = clients;
	return 0;
}

static int init_client_stream(struct gwhf_client_stream *cls)
{
	int ret;

	ret = gwhf_init_req_buf(cls);
	if (unlikely(ret))
		return ret;

	ret = gwhf_init_res_buf(cls);
	if (unlikely(ret))
		goto out_req_buf;

	return 0;

out_req_buf:
	gwhf_destroy_req_buf(cls);
	return ret;
}

static void destroy_client_stream(struct gwhf_client_stream *cls)
{
	gwhf_destroy_req_buf(cls);
	gwhf_destroy_res_buf(cls);
}

static int init_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint16_t nr_streams, i;
	int err;

	nr_streams = 1u;
	streams = calloc(nr_streams, sizeof(*streams));
	if (unlikely(!streams))
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		err = init_client_stream(&streams[i]);
		if (unlikely(err))
			goto out_err;
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	return 0;

out_err:
	while (i--)
		destroy_client_stream(&streams[i]);
	free(streams);
	return err;
}

static void destroy_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint16_t nr_streams, i;

	streams = cl->streams;
	nr_streams = cl->nr_streams;
	if (!streams)
		return;

	for (i = 0; i < nr_streams; i++)
		destroy_client_stream(&streams[i]);
	free(streams);
}

__hot
struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_pop_stack16(&cs->stack, &idx);
	if (unlikely(ret))
		return GWHF_ERR_PTR(ret);

	cl = &cs->clients[idx];
	ret = init_client_streams(cl);
	if (unlikely(ret))
		goto out_err;

	return cl;

out_err:
	gwhf_push_stack16(&cs->stack, idx);
	return GWHF_ERR_PTR(ret);
}

void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx;
	int err;

	idx = (uint16_t)(cl - cs->clients);
	err = gwhf_push_stack16(&cs->stack, idx);
	assert(err == 0);
	(void)err;
}

void gwhf_reset_client(struct gwhf_client *cl)
{
	destroy_client_streams(cl);
}
