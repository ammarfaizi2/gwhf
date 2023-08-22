// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef GWHF__CLIENT_H
#define GWHF__CLIENT_H

#include <gwhf/stack.h>
#include <gwhf/gwhf.h>

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct gwhf_stack16	stack;
};

int gwhf_client_init_slot(struct gwhf_client_slot *gwhf, uint32_t max_clients);
void gwhf_client_destroy_slot(struct gwhf_client_slot *gwhf);

#endif /* #ifndef GWHF__CLIENT_H */
