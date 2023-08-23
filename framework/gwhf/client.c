// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./ssl.h"
#include "./client.h"
#include "./internal.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define GWHF_RAW_BUF_INIT_SIZE 4096

static void init_client_first(struct gwhf_client *cl)
{
#ifdef _WIN32
	cl->fd.fd = INVALID_SOCKET;
#else
	cl->fd.fd = -1;
#endif
}

int gwhf_client_init_slot(struct gwhf_client_slot *gwhf, uint32_t max_clients)
{
	uint16_t i;
	int ret;

	ret = gwhf_stack16_init(&gwhf->stack, max_clients);
	if (ret)
		return ret;

	gwhf->clients = calloc(max_clients, sizeof(*gwhf->clients));
	if (!gwhf->clients) {
		gwhf_stack16_destroy(&gwhf->stack);
		return -ENOMEM;
	}

	i = max_clients;
	while (i--) {
		init_client_first(&gwhf->clients[i]);
		__gwhf_stack16_push(&gwhf->stack, i);
	}

	return 0;
}

void gwhf_client_destroy_slot(struct gwhf_client_slot *gwhf)
{
	if (!gwhf->clients)
		return;

	free(gwhf->clients);
	gwhf_stack16_destroy(&gwhf->stack);
}

static int gwhf_client_init_raw_buf(struct gwhf_raw_buf *rb)
{
	rb->buf = malloc(GWHF_RAW_BUF_INIT_SIZE);
	if (!rb->buf)
		return -ENOMEM;

	rb->alloc = GWHF_RAW_BUF_INIT_SIZE;
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

static int gwhf_client_update_raw_buf_alloc_len(struct gwhf_raw_buf *rb,
						uint32_t new_alloc)
{
	char *new_buf;

	new_buf = realloc(rb->buf, new_alloc);
	if (!new_buf)
		return -ENOMEM;

	rb->buf = new_buf;
	rb->alloc = new_alloc;
	return 0;
}

struct gwhf_client *gwhf_client_get(struct gwhf_client_slot *gwhf)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_stack16_pop(&gwhf->stack, &idx);
	if (ret < 0)
		return GWHF_ERR_PTR(ret);

	cl = &gwhf->clients[idx];

	ret = gwhf_client_init_raw_buf(&cl->recv_buf);
	if (unlikely(ret < 0))
		goto out_err;

	ret = gwhf_client_init_raw_buf(&cl->send_buf);
	if (unlikely(ret < 0))
		goto out_err_recv_buf;

	return cl;

out_err_recv_buf:
	gwhf_client_destroy_raw_buf(&cl->recv_buf);
out_err:
	gwhf_stack16_push(&gwhf->stack, idx);
	return GWHF_ERR_PTR(ret);
}

void gwhf_client_put(struct gwhf_client_slot *gwhf, struct gwhf_client *cl)
{
	uint16_t idx = cl - gwhf->clients;

	gwhf_sock_close(&cl->fd);
	gwhf_stack16_push(&gwhf->stack, idx);
}

int gwhf_client_get_recv_buf(struct gwhf_client *cl, void **buf_p, size_t *len_p)
{
	struct gwhf_raw_buf *rb = &cl->recv_buf;
	char *buf = cl->recv_buf.buf;
	uint32_t avail_len;
	int ret;

	avail_len = rb->alloc - rb->len;
	if (avail_len <= 1) {
		uint32_t new_alloc;

		new_alloc = rb->alloc * 2;
		ret = gwhf_client_update_raw_buf_alloc_len(rb, new_alloc);
		if (unlikely(ret < 0))
			return ret;

		avail_len = rb->alloc - rb->len;
		assert(new_alloc == rb->alloc);
	}

	*buf_p = buf + rb->len;
	*len_p = avail_len - 1;
	return 0;
}

void gwhf_client_advance_recv_buf(struct gwhf_client *cl, size_t len)
{
	struct gwhf_raw_buf *rb = &cl->recv_buf;
	char *buf = cl->recv_buf.buf;
	uint32_t new_len;

	new_len = rb->len + len;
	assert(new_len <= (rb->alloc - 1));

	rb->len = new_len;
	buf[new_len] = '\0';
}

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
