// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__SYSCALL_H
#define FRAMEWORK__GWHF__OS__LINUX__ARCH__SYSCALL_H

#include <syscall.h>
#include <stdint.h>

#if !defined(__x86_64__)
#include "x86/syscall.h"
#elif defined(__aarch64__)
#include "aarch64/syscall.h"
#else
#include "generic/syscall.h"
#endif

#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__SYSCALL_H */
