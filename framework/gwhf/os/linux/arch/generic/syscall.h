// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H
#define FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H

#include <syscall.h>
#include <stdint.h>

#define do_syscall0(N) ({			\
	uintptr_t ret = (uintptr_t)(N);		\
						\
	ret = syscall(ret);			\
						\
	(ret);					\
})

#define do_syscall1(N, A) ({			\
	uintptr_t ret = (uintptr_t)(N);		\
	uintptr_t arg1 = (uintptr_t)(A);	\
						\
	ret = syscall(ret, arg1);		\
						\
	(ret);					\
})

#define do_syscall2(N, A, B) ({			\
	uintptr_t ret = (uintptr_t)(N);		\
	uintptr_t arg1 = (uintptr_t)(A);	\
	uintptr_t arg2 = (uintptr_t)(B);	\
						\
	ret = syscall(ret, arg1, arg2);		\
						\
	(ret);					\
})

#define do_syscall3(N, A, B, C) ({		\
	uintptr_t ret = (uintptr_t)(N);		\
	uintptr_t arg1 = (uintptr_t)(A);	\
	uintptr_t arg2 = (uintptr_t)(B);	\
	uintptr_t arg3 = (uintptr_t)(C);	\
						\
	ret = syscall(ret, arg1, arg2, arg3);	\
						\
	(ret);					\
})

#define do_syscall4(N, A, B, C, D) ({			\
	uintptr_t ret = (uintptr_t)(N);			\
	uintptr_t arg1 = (uintptr_t)(A);		\
	uintptr_t arg2 = (uintptr_t)(B);		\
	uintptr_t arg3 = (uintptr_t)(C);		\
	uintptr_t arg4 = (uintptr_t)(D);		\
							\
	ret = syscall(ret, arg1, arg2, arg3, arg4);	\
							\
	(ret);						\
})

#define do_syscall5(N, A, B, C, D, E) ({			\
	uintptr_t ret = (uintptr_t)(N);				\
	uintptr_t arg1 = (uintptr_t)(A);			\
	uintptr_t arg2 = (uintptr_t)(B);			\
	uintptr_t arg3 = (uintptr_t)(C);			\
	uintptr_t arg4 = (uintptr_t)(D);			\
	uintptr_t arg5 = (uintptr_t)(E);			\
								\
	ret = syscall(ret, arg1, arg2, arg3, arg4, arg5);	\
								\
	(ret);							\
})

#define do_syscall6(N, A, B, C, D, E, F) ({			\
	uintptr_t ret = (uintptr_t)(N);				\
	uintptr_t arg1 = (uintptr_t)(A);			\
	uintptr_t arg2 = (uintptr_t)(B);			\
	uintptr_t arg3 = (uintptr_t)(C);			\
	uintptr_t arg4 = (uintptr_t)(D);			\
	uintptr_t arg5 = (uintptr_t)(E);			\
	uintptr_t arg6 = (uintptr_t)(F);			\
								\
	ret = syscall(ret, arg1, arg2, arg3, arg4, arg5, arg6);	\
								\
	(ret);							\
})


#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__GENERIC__SYSCALL_H */
