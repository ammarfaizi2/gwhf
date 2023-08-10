// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__STACK_H
#define GWHF__STACK_H

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

#endif /* #ifndef GWHF__STACK_H */
