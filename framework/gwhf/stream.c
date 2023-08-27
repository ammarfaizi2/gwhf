// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./stream.h"
#include "./buf.h"

#include <stdlib.h>
#include <string.h>

int gwhf_stream_init(struct gwhf_client_stream *str)
{
	int ret;

	ret = gwhf_buf_init(&str->req_buf);
	if (ret)
		return ret;

	ret = gwhf_buf_init(&str->res_buf);
	if (ret)
		goto out_req_buf;

	ret = gwhf_http_req_init(&str->req);
	if (ret)
		goto out_res_buf;

	ret = gwhf_http_res_init(&str->res);
	if (ret)
		goto out_req;

	str->sent_len = 0;
	str->state = TCL_IDLE;
	return 0;

out_req:
	gwhf_http_req_destroy(&str->req);
out_res_buf:
	gwhf_buf_destroy(&str->res_buf);
out_req_buf:
	gwhf_buf_destroy(&str->req_buf);
	return ret;
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
	cl->cur_stream = 0;
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

	if (!cl->streams)
		return;

	while (i--)
		gwhf_stream_destroy(&cl->streams[i]);

	free(cl->streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

void gwhf_stream_destroy(struct gwhf_client_stream *str)
{
	gwhf_buf_destroy(&str->req_buf);
	gwhf_buf_destroy(&str->res_buf);
	gwhf_http_req_destroy(&str->req);
	gwhf_http_res_destroy(&str->res);
}
