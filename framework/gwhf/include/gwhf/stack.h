// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__STACK_H
#define FRAMEWORK__GWHF__INCLUDE__GWHF__STACK_H

#include <gwhf/common.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_stack16 {
	uint16_t	*data;
	void		*lock;
	uint16_t	top;
	uint16_t	size;
};

GWHF_EXPORT int gwhf_stack16_init(struct gwhf_stack16 *stack, uint16_t size);
GWHF_EXPORT void gwhf_stack16_destroy(struct gwhf_stack16 *stack);
GWHF_EXPORT int gwhf_stack16_push(struct gwhf_stack16 *stack, uint16_t data);
GWHF_EXPORT int __gwhf_stack16_push(struct gwhf_stack16 *stack, uint16_t data);
GWHF_EXPORT int gwhf_stack16_pop(struct gwhf_stack16 *stack, uint16_t *data);
GWHF_EXPORT int __gwhf_stack16_pop(struct gwhf_stack16 *stack, uint16_t *data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__STACK_H */
