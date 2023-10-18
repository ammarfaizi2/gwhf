// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H
#define FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H

#include <syscall.h>
#include <stdint.h>
#include <errno.h>

#define do_syscall0(N) ({			\
	intptr_t ret = (uintptr_t)(N);		\
						\
	ret = syscall(ret);			\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall1(N, A) ({			\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
						\
	ret = syscall(ret, a);			\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall2(N, A, B) ({			\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
	__typeof__(B) b = (B);			\
						\
	ret = syscall(ret, a, b);		\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall3(N, A, B, C) ({		\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
	__typeof__(B) b = (B);			\
	__typeof__(C) c = (C);			\
						\
	ret = syscall(ret, a, b, c);		\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall4(N, A, B, C, D) ({		\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
	__typeof__(B) b = (B);			\
	__typeof__(C) c = (C);			\
	__typeof__(D) d = (D);			\
						\
	ret = syscall(ret, a, b, c, d);		\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall5(N, A, B, C, D, E) ({	\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
	__typeof__(B) b = (B);			\
	__typeof__(C) c = (C);			\
	__typeof__(D) d = (D);			\
	__typeof__(E) e = (E);			\
						\
	ret = syscall(ret, a, b, c, d, e);	\
						\
	(ret == -1 ? -errno : ret);		\
})

#define do_syscall6(N, A, B, C, D, E, F) ({	\
	intptr_t ret = (uintptr_t)(N);		\
	__typeof__(A) a = (A);			\
	__typeof__(B) b = (B);			\
	__typeof__(C) c = (C);			\
	__typeof__(D) d = (D);			\
	__typeof__(E) e = (E);			\
	__typeof__(F) f = (F);			\
						\
	ret = syscall(ret, a, b, c, d, e, f);	\
						\
	(ret == -1 ? -errno : ret);		\
})

#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H */
