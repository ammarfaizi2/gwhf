// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__STACK_H
#define GWHF__STACK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <pthread.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_stack16 {
	uint16_t	*data;
	uint16_t	top;
	uint16_t	size;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
};

GWHF_EXPORT int gwhf_init_stack16(struct gwhf_stack16 *stack, uint16_t size);
GWHF_EXPORT void gwhf_destroy_stack16(struct gwhf_stack16 *stack);
GWHF_EXPORT int gwhf_push_stack16(struct gwhf_stack16 *stack, uint16_t data);
GWHF_EXPORT int __gwhf_push_stack16(struct gwhf_stack16 *stack, uint16_t data);
GWHF_EXPORT int gwhf_pop_stack16(struct gwhf_stack16 *stack, uint16_t *data);
GWHF_EXPORT int __gwhf_pop_stack16(struct gwhf_stack16 *stack, uint16_t *data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__STACK_H */
