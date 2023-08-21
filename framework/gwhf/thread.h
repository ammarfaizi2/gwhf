// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__THREAD_H
#define FRAMEWORK__GWHF__THREAD_H

#include <stdint.h>
#include <stdarg.h>
#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_POSIX_THREAD
#include <pthread.h>
typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
#else /* #ifdef USE_POSIX_THREAD */
/*
 * Windows doesn't have C11 thread. Use a similar small
 * library to substitute it.
 */
#ifdef GWHF_OS_WIN32
#include "ext/tinycthread/tinycthread.h"
#else
#include <threads.h>
#endif
struct c11_thread;
typedef struct c11_thread *thread_t;
typedef mtx_t mutex_t;
typedef cnd_t cond_t;
#endif /* #ifdef USE_POSIX_THREAD */

int thread_create(thread_t *thread, void *(*func)(void *), void *arg);
int thread_join(thread_t thread, void **retval);
int thread_detach(thread_t thread);
int thread_equal(thread_t t1, thread_t t2);
int thread_setname(thread_t thread, const char *fmt, ...);

int mutex_init(mutex_t *mutex);
int mutex_destroy(mutex_t *mutex);
int mutex_lock(mutex_t *mutex);
int mutex_trylock(mutex_t *mutex);
int mutex_unlock(mutex_t *mutex);
int mutex_timedlock(mutex_t *mutex, const struct timespec *abstime);

int cond_init(cond_t *cond);
int cond_destroy(cond_t *cond);
int cond_wait(cond_t *cond, mutex_t *mutex);
int cond_timedwait(cond_t *cond, mutex_t *mutex, const struct timespec *abstime);
int cond_signal(cond_t *cond);
int cond_broadcast(cond_t *cond);
int cond_broadcast_n(cond_t *cond, uint32_t n);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* #ifndef FRAMEWORK__GWHF__THREAD_H */
