// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./client.h"
#include "./internal.h"

#include <stdlib.h>

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
#ifdef _WIN32
		gwhf->clients[i].fd.fd = INVALID_SOCKET;
#else
		gwhf->clients[i].fd.fd = -1;
#endif
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

struct gwhf_client *gwhf_client_get(struct gwhf_client_slot *gwhf)
{
	struct gwhf_client *cl;
	uint16_t idx;
	int ret;

	ret = gwhf_stack16_pop(&gwhf->stack, &idx);
	if (unlikely(ret < 0))
		return GWHF_ERR_PTR(ret);

	cl = &gwhf->clients[idx];
	return cl;
}

void gwhf_client_put(struct gwhf_client_slot *gwhf, struct gwhf_client *cl)
{
	uint16_t idx;

	gwhf_sock_close(&cl->fd);
	idx = cl - gwhf->clients;
	gwhf_stack16_push(&gwhf->stack, idx);
}
