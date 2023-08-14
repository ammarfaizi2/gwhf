// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <stdlib.h>
#include <string.h>

#include "client.h"

static void init_client_first_time(struct gwhf_client *cl)
{
#if defined(_WIN32)
	cl->fd.fd = INVALID_SOCKET;
#else
	cl->fd.fd = -1;
#endif
}

static void destroy_client(struct gwhf_client *cl)
{
	gwhf_sock_close(&cl->fd);
	gwhf_destroy_client_streams(cl);
	gwhf_destroy_client_ssl_buf(cl);
}

int gwhf_init_client_slot(struct gwhf_client_slot *cs, size_t nr_clients)
{
	struct gwhf_client *clients;
	uint32_t i;
	int ret;

	clients = calloc(nr_clients, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = gwhf_stack16_init(&cs->stack, nr_clients);
	if (ret) {
		free(clients);
		return ret;
	}

	i = nr_clients;
	while (i--) {
		init_client_first_time(&clients[i]);
		ret = gwhf_stack16_push(&cs->stack, i);
		assert(!ret);
		(void)ret;
	}

	cs->clients = clients;
	return 0;
}

void gwhf_destroy_client_slot(struct gwhf_client_slot *cs)
{
	struct gwhf_client *clients = cs->clients;
	uint16_t i;

	if (!clients)
		return;

	for (i = 0; i < cs->stack.size; i++)
		destroy_client(&clients[i]);

	gwhf_stack16_destroy(&cs->stack);
	free(clients);
	memset(cs, 0, sizeof(*cs));
}

void gwhf_soft_reset_client(struct gwhf_client *cl)
{
	gwhf_destroy_client_streams(cl);
	gwhf_destroy_client_ssl_buf(cl);
}

int gwhf_reset_current_stream(struct gwhf_client *cl)
{
	struct gwhf_client_stream new_str, *cs = gwhf_client_get_cur_stream(cl);
	int ret;

	gwhf_destroy_client_stream(cs);
	ret = gwhf_init_client_stream(&new_str);
	if (unlikely(ret))
		return ret;

	*cs = new_str;
	return 0;
}

void gwhf_reset_client(struct gwhf_client *cl)
{
	gwhf_sock_close(&cl->fd);
}

static void assert_get_client(struct gwhf_client *cl)
{
#if defined(_WIN32)
	assert(cl->fd.fd == INVALID_SOCKET);
#else
	assert(cl->fd.fd == -1);
#endif

	assert(!cl->streams);
	assert(!cl->nr_streams);
	assert(!cl->cur_stream);

	(void)cl;
}

struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int err, ret;

	ret = gwhf_stack16_pop(&cs->stack, &idx);
	if (unlikely(ret))
		return GWHF_ERR_PTR(ret);

	cl = &cs->clients[idx];
	assert_get_client(cl);

	err = gwhf_init_client_streams(cl, 1);
	if (unlikely(err))
		goto out_push;

	err = gwhf_init_client_ssl_buf(cl);
	if (unlikely(err))
		goto out_client_stream;

	return cl;

out_client_stream:
	gwhf_destroy_client_streams(cl);
out_push:
	ret = gwhf_stack16_push(&cs->stack, idx);
	assert(!ret);
	return GWHF_ERR_PTR(err);
}

void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx = cl - cs->clients;
	int ret;

	gwhf_reset_client(cl);
	ret = gwhf_stack16_push(&cs->stack, idx);
	assert(!ret);
	(void)ret;
}
