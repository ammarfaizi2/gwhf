// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./client.h"
#include "./stream.h"
#include "./internal.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static int gwhf_client_init_raw_buf(struct gwhf_raw_buf *rb)
{
	rb->buf = malloc(4096);
	if (!rb->buf)
		return -ENOMEM;

	rb->alloc = 4096;
	rb->len = 0;
	return 0;
}

static void gwhf_client_destroy_raw_buf(struct gwhf_raw_buf *rb)
{
	if (!rb->buf)
		return;

	free(rb->buf);
	memset(rb, 0, sizeof(*rb));
}

static void init_client_first(struct gwhf_client *cl)
{
#ifdef _WIN32
	cl->fd.fd = INVALID_SOCKET;
#else
	cl->fd.fd = -1;
#endif
}

static void reset_client(struct gwhf_client *cl)
{
	gwhf_sock_close(&cl->fd);
	gwhf_client_destroy_raw_buf(&cl->send_buf);
	gwhf_client_destroy_raw_buf(&cl->recv_buf);
}

__cold
int gwhf_client_init_slot(struct gwhf_client_slot *cs, uint32_t max_clients)
{
	uint16_t i;
	int ret;

	ret = gwhf_stack16_init(&cs->stack, max_clients);
	if (ret)
		return ret;

	cs->clients = calloc(max_clients, sizeof(*cs->clients));
	if (!cs->clients) {
		gwhf_stack16_destroy(&cs->stack);
		return -ENOMEM;
	}

	i = max_clients;
	while (i--) {
		init_client_first(&cs->clients[i]);
		__gwhf_stack16_push(&cs->stack, i);
	}

	return 0;
}

__cold
void gwhf_client_destroy_slot(struct gwhf_client_slot *cs)
{
	uint16_t i;

	if (!cs->clients)
		return;

	i = cs->stack.size;
	while (i--)
		reset_client(&cs->clients[i]);

	free(cs->clients);
	gwhf_stack16_destroy(&cs->stack);
}

__hot
struct gwhf_client *gwhf_client_get(struct gwhf_client_slot *cs)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_stack16_pop(&cs->stack, &idx);
	if (unlikely(ret))
		return GWHF_ERR_PTR(ret);

	cl = &cs->clients[idx];

	ret = gwhf_client_init_raw_buf(&cl->recv_buf);
	if (unlikely(ret))
		goto out_put;

	ret = gwhf_client_init_raw_buf(&cl->send_buf);
	if (unlikely(ret))
		goto out_recv_buf;

	ret = gwhf_stream_init_all(cl, 1);
	if (unlikely(ret))
		goto out_send_buf;

	return cl;

out_send_buf:
	gwhf_client_destroy_raw_buf(&cl->send_buf);
out_recv_buf:
	gwhf_client_destroy_raw_buf(&cl->recv_buf);
out_put:
	gwhf_stack16_push(&cs->stack, idx);
	return GWHF_ERR_PTR(ret);
}

__hot
void gwhf_client_put(struct gwhf_client_slot *cs, struct gwhf_client *cl)
{
	uint16_t idx;

	idx = cl - cs->clients;
	assert(idx < cs->stack.size);

	reset_client(cl);
	gwhf_stack16_push(&cs->stack, idx);
}

__hot
int gwhf_client_get_recv_buf(struct gwhf_client *cl, void **buf, size_t *len)
{
	return 0;
}

__hot
void gwhf_client_advance_recv_buf(struct gwhf_client *cl, size_t len)
{
}

__hot
int gwhf_client_consume_recv_buf(struct gwhf_client *cl)
{
	return 0;
}

int gwhf_client_get_send_buf(struct gwhf_client *cl, const void **buf, size_t *len)
{
	return 0;
}

void gwhf_client_advance_send_buf(struct gwhf_client *cl, size_t len)
{
}
