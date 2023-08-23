// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./stream.h"

#include <stdlib.h>
#include <string.h>

static int init_stream_buf(struct gwhf_client_stream_buf *csb)
{
	csb->buf = malloc(4096);
	if (!csb->buf)
		return -ENOMEM;

	csb->alloc = 4096;
	csb->len = 0;
	return 0;
}

static void destroy_stream_buf(struct gwhf_client_stream_buf *csb)
{
	if (!csb->buf)
		return;

	free(csb->buf);
	csb->buf = NULL;
	memset(csb, 0, sizeof(*csb));
}

int gwhf_stream_init(struct gwhf_client_stream *str)
{
	int ret;

	ret = init_stream_buf(&str->req_buf);
	if (ret)
		return ret;

	ret = init_stream_buf(&str->res_buf);
	if (ret) {
		destroy_stream_buf(&str->req_buf);
		return ret;
	}

	str->sent_len = 0;
	return 0;
}

int gwhf_stream_init_all(struct gwhf_client *cl, uint32_t nr_streams)
{
	struct gwhf_client_stream *streams;
	uint32_t i;
	int ret;

	streams = calloc(nr_streams, sizeof(*streams));
	if (!streams)
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		ret = gwhf_stream_init(&streams[i]);
		if (ret)
			goto out_err;
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	return 0;

out_err:
	while (i--)
		gwhf_stream_destroy(&streams[i]);

	free(streams);
	return ret;
}

void gwhf_stream_destroy_all(struct gwhf_client *cl)
{
	uint32_t i = cl->nr_streams;

	while (i--)
		gwhf_stream_destroy(&cl->streams[i]);

	free(cl->streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

void gwhf_stream_destroy(struct gwhf_client_stream *str)
{
	destroy_stream_buf(&str->req_buf);
	destroy_stream_buf(&str->res_buf);
}
