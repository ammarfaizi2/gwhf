// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__CLIENT_H
#define FRAMEWORK__GWHF__CLIENT_H

#include <gwhf/client.h>
#include <gwhf/stack.h>

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct gwhf_stack16	stack;
};

#include "internal.h"

int gwhf_init_client_slot(struct gwhf_client_slot *cs, size_t nr_clients);
void gwhf_destroy_client_slot(struct gwhf_client_slot *cs);
struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs);
void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl);
void gwhf_soft_reset_client(struct gwhf_client *cl);
void gwhf_reset_client(struct gwhf_client *cl);
int gwhf_reset_current_stream(struct gwhf_client *cl);

#endif /* #ifndef FRAMEWORK__GWHF__CLIENT_H */
