// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include "internal.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>

__cold
int gwhf_stack16_init(struct gwhf_stack16 *s16, uint16_t size)
{
	uint16_t *data;
	int err;

	data = malloc(sizeof(*data) * size);
	if (data == NULL)
		return -ENOMEM;

	err = pthread_mutex_init(&s16->lock, NULL);
	if (err != 0) {
		free(data);
		return -err;
	}

	err = pthread_cond_init(&s16->cond, NULL);
	if (err != 0) {
		pthread_mutex_destroy(&s16->lock);
		free(data);
		return -err;
	}

	s16->top = 0;
	s16->size = size;
	s16->data = data;
	return 0;
}

__cold
void gwhf_stack16_destroy(struct gwhf_stack16 *s16)
{
	if (s16->data) {
		free(s16->data);
		pthread_mutex_destroy(&s16->lock);
		pthread_cond_destroy(&s16->cond);
		memset(s16, 0, sizeof(*s16));
	}
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
	int err;

	pthread_mutex_lock(&s16->lock);
	err = __gwhf_push_stack16(s16, num);
	pthread_mutex_unlock(&s16->lock);
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
	int err;

	pthread_mutex_lock(&s16->lock);
	err = __gwhf_pop_stack16(s16, num);
	pthread_mutex_unlock(&s16->lock);
	return err;
}
