// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#include <gwhf/stack.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

struct stack_lock {
	mutex_t	lock;
};

__cold
int gwhf_stack16_init(struct gwhf_stack16 *s16, uint16_t size)
{
	struct stack_lock *lock;
	uint16_t *data;
	int err;

	data = malloc(sizeof(*data) * size);
	if (!data)
		return -ENOMEM;

	lock = malloc(sizeof(*lock));
	if (!lock) {
		free(data);
		return -ENOMEM;
	}

	err = mutex_init(&lock->lock);
	if (err) {
		free(data);
		free(lock);
		return err;
	}

	s16->top = 0;
	s16->size = size;
	s16->data = data;
	s16->lock = lock;
	return 0;
}

__cold
void gwhf_stack16_destroy(struct gwhf_stack16 *s16)
{
	struct stack_lock *lock;

	if (!s16->data)
		return;

	lock = s16->lock;
	mutex_destroy(&lock->lock);
	free(lock);
	free(s16->data);
	memset(s16, 0, sizeof(*s16));
}

int __gwhf_stack16_push(struct gwhf_stack16 *s16, uint16_t num)
{
	if (unlikely(s16->top == s16->size))
		return -EAGAIN;

	s16->data[s16->top++] = num;
	return 0;
}

int gwhf_stack16_push(struct gwhf_stack16 *s16, uint16_t num)
{
	struct stack_lock *lock = s16->lock;
	int err;

	mutex_lock(&lock->lock);
	err = __gwhf_stack16_push(s16, num);
	mutex_unlock(&lock->lock);
	return err;
}

int __gwhf_stack16_pop(struct gwhf_stack16 *s16, uint16_t *num)
{
	if (unlikely(s16->top == 0))
		return -EAGAIN;

	*num = s16->data[--s16->top];
	return 0;
}

int gwhf_stack16_pop(struct gwhf_stack16 *s16, uint16_t *num)
{
	struct stack_lock *lock = s16->lock;
	int err;

	mutex_lock(&lock->lock);
	err = __gwhf_stack16_pop(s16, num);
	mutex_unlock(&lock->lock);
	return err;
}
