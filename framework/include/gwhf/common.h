// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__COMMON_H
#define GWHF__COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

#endif /* #ifndef GWHF__COMMON_H */
