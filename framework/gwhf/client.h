// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef GWHF__CLIENT_H
#define GWHF__CLIENT_H

#include <gwhf/stack.h>
#include <gwhf/gwhf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct gwhf_stack16	stack;
};

int gwhf_client_init_slot(struct gwhf_client_slot *cs, uint32_t max_clients);
void gwhf_client_destroy_slot(struct gwhf_client_slot *cs);
struct gwhf_client *gwhf_client_get(struct gwhf_client_slot *cs);
void gwhf_client_put(struct gwhf_client_slot *cs, struct gwhf_client *cl);

int gwhf_client_get_recv_buf(struct gwhf_client *cl, void **buf, size_t *len);
void gwhf_client_advance_recv_buf(struct gwhf_client *cl, size_t len);
int gwhf_client_consume_recv_buf(struct gwhf *ctx, struct gwhf_client *cl);

int gwhf_client_get_send_buf(struct gwhf_client *cl, const void **buf, size_t *len);
void gwhf_client_advance_send_buf(struct gwhf_client *cl, size_t len);
bool gwhf_client_has_send_buf(struct gwhf_client *cl);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__CLIENT_H */
