// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__COMMON_H
#define FRAMEWORK__GWHF__INCLUDE__GWHF__COMMON_H

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
#include <stddef.h>
#include <errno.h>

#ifndef GWHF_EXPORT
#define GWHF_EXPORT __attribute__((__visibility__("default")))
#endif

#ifdef __GNUC__
#define __gwhf_printf(a, b) __attribute__((__format__(__printf__, a, b)))
#else
#define __gwhf_printf(a, b)
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
	return __builtin_expect((uintptr_t)ptr > (uintptr_t)-4096ul, 0);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__COMMON_H */
