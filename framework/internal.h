// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__INTERNAL_H
#define GWHF__FRAMEWORK__INTERNAL_H

#include <gwhf/gwhf.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "helpers.h"

#ifndef __cold
#define __cold __attribute__((__cold__))
#endif

#ifndef __hot
#define __hot __attribute__((__hot__))
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#ifndef noinline
#define noinline __attribute__((__noinline__))
#endif

#ifndef __always_inline
#define __always_inline __attribute__((__always_inline__))
#endif

#endif /* #ifndef GWHF__FRAMEWORK__INTERNAL_H */
