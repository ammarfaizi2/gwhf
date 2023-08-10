// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__COMMON_H
#define GWHF__COMMON_H

#if defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef POSIX_C_SOURCE
#define POSIX_C_SOURCE 200809L
#endif

#endif /* #if defined(__linux__) */

#include <stdbool.h>
#include <stdint.h>

#ifndef GWHF_EXPORT
#define GWHF_EXPORT __attribute__((__visibility__("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline void *GWHF_ERR_PTR(intptr_t err)
{
	return (void *)err;
}

static inline intptr_t GWHF_PTR_ERR(const void *ptr)
{
	return (intptr_t)ptr;
}

static inline bool GWHF_IS_ERR(const void *ptr)
{
	return (uintptr_t)ptr > (uintptr_t)-4096ul;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef GWHF__COMMON_H */
