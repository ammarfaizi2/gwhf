// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "internal.h"
#include "ev/epoll.h"
#include "http/request.h"
#include "http/response.h"

#include <string.h>
#include <stdio.h>

int gwhf_exec_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	(void)ctx;
	(void)cl;
	return 0;
}

int gwhf_exec_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	(void)ctx;

	cl->streams[0].state = T_CL_STREAM_SEND_HEADER;
	return 0;
}

void gwhf_destroy_route_header(struct gwhf_internal *it)
{
	free(it->route_header);
	it->route_header = NULL;
	it->nr_route_header = 0;
}

void gwhf_destroy_route_body(struct gwhf_internal *it)
{
	free(it->route_body);
	it->route_body = NULL;
	it->nr_route_body = 0;
}

int gwhf_add_route_header(struct gwhf *ctx,
			  int (*callback)(struct gwhf *, struct gwhf_client *))
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_header *hdr;
	size_t new_nr;

	if (!it)
		return -EFAULT;

	new_nr = (size_t)it->nr_route_header + 1;
	if (new_nr > 65535)
		return -ENOMEM;

	hdr = realloc(it->route_header, sizeof(*hdr) * new_nr);
	if (!hdr)
		return -ENOMEM;

	it->route_header = hdr;
	it->nr_route_header = (uint16_t)new_nr;
	it->route_header[new_nr - 1].exec_cb = callback;
	return 0;
}

int gwhf_add_route_body(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *))
{
	struct gwhf_internal *it = gwhf_get_internal(ctx);
	struct gwhf_route_body *body;
	size_t new_nr;

	if (!it)
		return -EFAULT;

	new_nr = (size_t)it->nr_route_body + 1;
	if (new_nr > 65535)
		return -ENOMEM;

	body = realloc(it->route_body, sizeof(*body) * new_nr);
	if (!body)
		return -ENOMEM;

	it->route_body = body;
	it->nr_route_body = (uint16_t)new_nr;
	it->route_body[new_nr - 1].exec_cb = callback;
	return 0;
}
