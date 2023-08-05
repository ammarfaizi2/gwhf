// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "client.h"
#include "http/request.h"
#include "http/response.h"
#include "http/stream.h"

static int init_client(struct gwhf_client *cl)
{
	cl->fd = -1;
	return 0;
}

static void destroy_client(struct gwhf_client *cl)
{
	if (cl->fd >= 0) {
		close(cl->fd);
		cl->fd = -1;
	}

	if (cl->streams)
		gwhf_destroy_client_streams(cl);
}

__cold
int gwhf_init_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	struct gwhf_init_arg *arg = &ctx->init_arg;
	uint16_t i;
	int err;

	cs->clients = calloc(arg->nr_clients, sizeof(*cs->clients));
	if (!cs->clients)
		return -ENOMEM;

	err = gwhf_init_stack16(&cs->stack, arg->nr_clients);
	if (err) {
		free(cs->clients);
		cs->clients = NULL;
		return err;
	}

	i = arg->nr_clients;
	while (i--) {
		init_client(cs->clients + i);
		err = __gwhf_push_stack16(&cs->stack, i);
		assert(!err);
		(void)err;
	}

	return 0;
}

__cold
void gwhf_destroy_client_slot(struct gwhf *ctx)
{
	struct gwhf_client_slot *cs = &ctx->client_slot;
	uint16_t i;

	if (!cs->clients)
		return;

	for (i = 0; i < cs->stack.size; i++)
		destroy_client(cs->clients + cs->stack.data[i]);
}

__hot
struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_pop_stack16(&cs->stack, &idx);
	if (ret)
		return GWHF_ERR_PTR(ret);

	cl = cs->clients + idx;
	assert(cl->fd == -1);
	assert(!cl->private_data);
	assert(!cl->streams);
	assert(!cl->nr_streams);
	assert(!cl->pollout_set);

	ret = gwhf_init_client_streams(cl, 1);
	if (ret) {
		gwhf_push_stack16(&cs->stack, idx);
		return GWHF_ERR_PTR(ret);
	}

	return cl;
}

__hot
void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx;
	int ret;

	if (cl->fd >= 0) {
		close(cl->fd);
		cl->fd = -1;
	}

	cl->private_data = NULL;
	cl->pollout_set = false;

	if (cl->streams)
		gwhf_destroy_client_streams(cl);

	idx = (uint16_t)(cl - cs->clients);
	ret = gwhf_push_stack16(&cs->stack, idx);
	assert(!ret);
	(void)ret;
}
