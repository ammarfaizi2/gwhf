// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__X86__SYSCALL_H
#define FRAMEWORK__GWHF__OS__LINUX__ARCH__X86__SYSCALL_H

#include <syscall.h>
#include <stdint.h>

#define do_syscall0(N) ({			\
	intptr_t rax = (intptr_t)(N);		\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a"(rax) /* %rax */		\
		:				\
		: "rcx", "r11", "memory"	\
	);					\
						\
	(rax);					\
})

#define do_syscall1(N, A) ({			\
	intptr_t rax = (intptr_t)(N);		\
	__typeof__(A) rdi = (A);		\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a"(rax) /* %rax */		\
		: "D"(rdi)  /* %rdi */		\
		: "rcx", "r11", "memory"	\
	);					\
						\
	(rax);					\
})

#define do_syscall2(N, A, B) ({			\
	intptr_t rax = (intptr_t)(N);		\
	__typeof__(A) rdi = (A);		\
	__typeof__(B) rsi = (B);		\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a"(rax) /* %rax */		\
		: "D"(rdi), /* %rdi */		\
		  "S"(rsi)  /* %rsi */		\
		: "rcx", "r11", "memory"	\
	);					\
						\
	(rax);					\
})

#define do_syscall3(N, A, B, C) ({		\
	intptr_t rax = (intptr_t)(N);		\
	__typeof__(A) rdi = (A);		\
	__typeof__(B) rsi = (B);		\
	__typeof__(C) rdx = (C);		\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a"(rax) /* %rax */		\
		: "D"(rdi), /* %rdi */		\
		  "S"(rsi), /* %rsi */		\
		  "d"(rdx)  /* %rdx */		\
		: "rcx", "r11", "memory"	\
	);					\
						\
	(rax);					\
})

#define do_syscall4(N, A, B, C, D) ({				\
	intptr_t rax = (intptr_t)(N);				\
	__typeof__(A) rdi = (A);				\
	__typeof__(B) rsi = (B);				\
	__typeof__(C) rdx = (C);				\
	register __typeof__(D) r10 __asm__("r10") = (D);	\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a"(rax) /* %rax */				\
		: "D"(rdi), /* %rdi */				\
		  "S"(rsi), /* %rsi */				\
		  "d"(rdx), /* %rdx */				\
		  "r"(r10)  /* %r10 */				\
		: "rcx", "r11", "memory"			\
	);							\
								\
	(rax);							\
})

#define do_syscall5(N, A, B, C, D, E) ({			\
	intptr_t rax = (intptr_t)(N);				\
	__typeof__(A) rdi = (A);				\
	__typeof__(B) rsi = (B);				\
	__typeof__(C) rdx = (C);				\
	register __typeof__(D) r10 __asm__("r10") = (D);	\
	register __typeof__(E) r8 __asm__("r8") = (E);		\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a"(rax) /* %rax */				\
		: "D"(rdi), /* %rdi */				\
		  "S"(rsi), /* %rsi */				\
		  "d"(rdx), /* %rdx */				\
		  "r"(r10), /* %r10 */				\
		  "r"(r8)   /* %r8 */				\
		: "rcx", "r11", "memory"			\
	);							\
								\
	(rax);							\
})

#define do_syscall6(N, A, B, C, D, E, F) ({			\
	intptr_t rax = (intptr_t)(N);				\
	__typeof__(A) rdi = (A);				\
	__typeof__(B) rsi = (B);				\
	__typeof__(C) rdx = (C);				\
	register __typeof__(D) r10 __asm__("r10") = (D);	\
	register __typeof__(E) r8 __asm__("r8") = (E);		\
	register __typeof__(F) r9 __asm__("r9") = (F);		\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a"(rax) /* %rax */				\
		: "D"(rdi), /* %rdi */				\
		  "S"(rsi), /* %rsi */				\
		  "d"(rdx), /* %rdx */				\
		  "r"(r10), /* %r10 */				\
		  "r"(r8),  /* %r8 */				\
		  "r"(r9)   /* %r9 */				\
		: "rcx", "r11", "memory"			\
	);							\
								\
	(rax);							\
})


#endif /* #ifndef FRAMEWORK__GWHF__OS__LINUX__ARCH__X86__SYSCALL_H */
