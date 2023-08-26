// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

__cold
int gwhf_stack16_init(struct gwhf_stack16 *stack, uint16_t size)
{
	uint16_t *data;
	mutex_t *lock;

	data = malloc(sizeof(*data) * size);
	if (!data)
		return -ENOMEM;

	lock = malloc(sizeof(*lock));
	if (!lock) {
		free(data);
		return -ENOMEM;
	}

	if (mutex_init(lock)) {
		free(data);
		free(lock);
		return -ENOMEM;
	}

	stack->top = 0;
	stack->size = size;
	stack->data = data;
	stack->lock = lock;
	return 0;
}

__cold
void gwhf_stack16_destroy(struct gwhf_stack16 *stack)
{
	mutex_t *lock;

	if (!stack->data)
		return;

	lock = stack->lock;
	mutex_destroy(lock);
	free(lock);
	free(stack->data);
	memset(stack, 0, sizeof(*stack));
}

int gwhf_stack16_push(struct gwhf_stack16 *stack, uint16_t data)
{
	mutex_t *lock = stack->lock;
	int ret;

	mutex_lock(lock);
	ret = __gwhf_stack16_push(stack, data);
	mutex_unlock(lock);
	return ret;
}

int __gwhf_stack16_push(struct gwhf_stack16 *stack, uint16_t data)
{
	if (unlikely(stack->top == stack->size))
		return -EAGAIN;

	stack->data[stack->top++] = data;
	return 0;
}

int gwhf_stack16_pop(struct gwhf_stack16 *stack, uint16_t *data)
{
	mutex_t *lock = stack->lock;
	int ret;

	mutex_lock(lock);
	ret = __gwhf_stack16_pop(stack, data);
	mutex_unlock(lock);
	return ret;
}

int __gwhf_stack16_pop(struct gwhf_stack16 *stack, uint16_t *data)
{
	if (unlikely(stack->top == 0))
		return -EAGAIN;

	*data = stack->data[--stack->top];
	return 0;
}
