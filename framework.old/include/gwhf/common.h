// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__COMMON_H
#define GWHF__COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GWHF_EXPORT
#define GWHF_EXPORT __attribute__((__visibility__("default")))
#endif

static inline void *GWHF_ERR_PTR(long err)
{
	return (void *)err;
}

static inline long GWHF_PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline bool GWHF_IS_ERR(const void *ptr)
{
	return (unsigned long)ptr > (unsigned long)-4096ul;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__COMMON_H */
