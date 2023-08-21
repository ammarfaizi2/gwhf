// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#ifndef GWHF__FRAMEWORK__HTTP__STREAM_H
#define GWHF__FRAMEWORK__HTTP__STREAM_H

#include "../internal.h"
#include <assert.h>

int gwhf_init_client_streams(struct gwhf_client *cl, uint32_t nr_streams);
void gwhf_destroy_client_streams(struct gwhf_client *cl);

/*
 * Use this for reusing the stream when keep-alive is enabled
 * to avoid destroying and reinitializing the stream.
 */
void gwhf_soft_reset_client_streams(struct gwhf_client *cl);

int gwhf_get_recv_buffer(struct gwhf_client *cl, void **buf_p, size_t *len_p);
void gwhf_advance_recv_buffer(struct gwhf_client *cl, size_t len);

int gwhf_get_send_buffer(struct gwhf_client *cl, const void **buf_p,
			 size_t *len_p);
void gwhf_advance_send_buffer(struct gwhf_client *cl, size_t len);

int gwhf_consume_client_recv_buf(struct gwhf *ctx, struct gwhf_client *cl);

static inline bool gwhf_client_has_pending_send(struct gwhf_client *cl)
{
	struct gwhf_client_stream *stream = &cl->streams[cl->cur_stream];
	uint8_t state = stream->state;

	return (state & (T_CL_STREAM_SEND_HEADER | T_CL_STREAM_SEND_BODY));
}

#endif /* #ifndef GWHF__FRAMEWORK__HTTP__STREAM_H */
