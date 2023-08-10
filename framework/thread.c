// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include "thread.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#ifdef USE_POSIX_THREAD
int thread_create(thread_t *thread, void *(*func)(void *), void *arg)
{
	return -pthread_create(thread, NULL, func, arg);
}

int thread_join(thread_t thread, void **retval)
{
	return -pthread_join(thread, retval);
}

int thread_detach(thread_t thread)
{
	return -pthread_detach(thread);
}

int thread_equal(thread_t t1, thread_t t2)
{
	return pthread_equal(t1, t2);
}

int thread_setname(thread_t thread, const char *fmt, ...)
{
	va_list ap;
	char buf[32];
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if ((size_t)ret >= sizeof(buf))
		return -ENAMETOOLONG;

	return -pthread_setname_np(thread, buf);
}

int mutex_init(mutex_t *mutex)
{
	return -pthread_mutex_init(mutex, NULL);
}

int mutex_destroy(mutex_t *mutex)
{
	return -pthread_mutex_destroy(mutex);
}

int mutex_lock(mutex_t *mutex)
{
	return -pthread_mutex_lock(mutex);
}

int mutex_trylock(mutex_t *mutex)
{
	return -pthread_mutex_trylock(mutex);
}

int mutex_unlock(mutex_t *mutex)
{
	return -pthread_mutex_unlock(mutex);
}

int mutex_timedlock(mutex_t *mutex, const struct timespec *abstime)
{
	return -pthread_mutex_timedlock(mutex, abstime);
}

int cond_init(cond_t *cond)
{
	return -pthread_cond_init(cond, NULL);
}

int cond_destroy(cond_t *cond)
{
	return -pthread_cond_destroy(cond);
}

int cond_wait(cond_t *cond, mutex_t *mutex)
{
	return -pthread_cond_wait(cond, mutex);
}

int cond_timedwait(cond_t *cond, mutex_t *mutex, const struct timespec *abstime)
{
	return -pthread_cond_timedwait(cond, mutex, abstime);
}

int cond_signal(cond_t *cond)
{
	return -pthread_cond_signal(cond);
}

int cond_broadcast(cond_t *cond)
{
	return -pthread_cond_broadcast(cond);
}

int cond_broadcast_n(cond_t *cond, uint32_t n)
{
	if (n == 0)
		return 0;

	if (n == 1)
		return cond_signal(cond);

	return -pthread_cond_broadcast(cond);
}

#else /* #ifdef USE_POSIX_THREAD */

struct c11_thread {
	thrd_t		thrd;
	_Atomic(int)	ref_cnt;
	union {
		void	*ret;
		void	*arg;
	};
	void		*(*func)(void *);
};

static int c11_thread_func_entry(void *arg)
{
	struct c11_thread *t;
	void *thread_arg;

	t = (struct c11_thread *)arg;
	thread_arg = t->arg;
	t->ret = t->func(thread_arg);

	/*
	 * If the reference count is 1, it means the caller has
	 * detached the thread, so we have to free the object.
	 */
	if (atomic_fetch_sub(&t->ref_cnt, 1) == 1)
		free(t);

	return 0;
}

int thread_create(thread_t *thread, void *(*func)(void *), void *arg)
{
	struct c11_thread *t;
	int ret;

	t = (struct c11_thread *)malloc(sizeof(*t));
	if (!t)
		return -ENOMEM;

	t->func = func;
	t->arg = arg;

	/*
	 * Set this to 2 because there will be 2 references:
	 *   1. The thread itself.
	 *   2. The caller.
	 */
	atomic_store(&t->ref_cnt, 2);
	ret = thrd_create(&t->thrd, c11_thread_func_entry, t);
	if (ret != thrd_success) {
		free(t);
		return -ENOMEM;
	}

	*thread = t;
	return 0;
}

int thread_join(thread_t thread, void **retval)
{
	struct c11_thread *t = (struct c11_thread *)thread;
	int ret;

	ret = thrd_join(t->thrd, NULL);
	if (ret != thrd_success)
		return -EINVAL;

	if (retval)
		*retval = t->ret;

	assert(atomic_load(&t->ref_cnt) == 1);
	free(t);
	return 0;
}

int thread_detach(thread_t thread)
{
	struct c11_thread *t = (struct c11_thread *)thread;
	int ret;

	ret = thrd_detach(t->thrd);
	if (ret != thrd_success)
		return -EINVAL;

	/*
	 * If the reference count is 1, it means the thread has
	 * already exited before the caller detaches the thread,
	 * so we have to free the object.
	 */
	if (atomic_fetch_sub(&t->ref_cnt, 1) == 1)
		free(t);

	return 0;
}

int thread_equal(thread_t t1, thread_t t2)
{
	struct c11_thread *t1_ = (struct c11_thread *)t1;
	struct c11_thread *t2_ = (struct c11_thread *)t2;
	return thrd_equal(t1_->thrd, t2_->thrd);
}

int thread_setname(thread_t thread, const char *fmt, ...)
{
	(void)thread;
	(void)fmt;
	return 0;
}

int mutex_init(mutex_t *mutex)
{
	int ret;

	ret = mtx_init(mutex, mtx_plain);
	if (ret != thrd_success)
		return -ENOMEM;

	return 0;
}

int mutex_destroy(mutex_t *mutex)
{
	mtx_destroy(mutex);
	return 0;
}

int mutex_lock(mutex_t *mutex)
{
	int ret;

	ret = mtx_lock(mutex);
	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int mutex_trylock(mutex_t *mutex)
{
	int ret;

	ret = mtx_trylock(mutex);
	if (ret == thrd_busy)
		return -EBUSY;

	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int mutex_unlock(mutex_t *mutex)
{
	int ret;

	ret = mtx_unlock(mutex);
	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int mutex_timedlock(mutex_t *mutex, const struct timespec *abstime)
{
	int ret;

	ret = mtx_timedlock(mutex, abstime);
	if (ret == thrd_busy)
		return -EBUSY;

	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int cond_init(cond_t *cond)
{
	int ret;

	ret = cnd_init(cond);
	if (ret != thrd_success)
		return -ENOMEM;

	return 0;
}

int cond_destroy(cond_t *cond)
{
	cnd_destroy(cond);
	return 0;
}

int cond_wait(cond_t *cond, mutex_t *mutex)
{
	int ret;

	ret = cnd_wait(cond, mutex);
	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int cond_timedwait(cond_t *cond, mutex_t *mutex, const struct timespec *abstime)
{
	int ret;

	ret = cnd_timedwait(cond, mutex, abstime);
	if (ret == thrd_busy)
		return -EBUSY;

	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int cond_signal(cond_t *cond)
{
	int ret;

	ret = cnd_signal(cond);
	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int cond_broadcast(cond_t *cond)
{
	int ret;

	ret = cnd_broadcast(cond);
	if (ret != thrd_success)
		return -EINVAL;

	return 0;
}

int cond_broadcast_n(cond_t *cond, uint32_t n)
{
	if (n == 0)
		return 0;
	if (n == 1)
		return cond_signal(cond);

	return cond_broadcast(cond);
}
#endif /* #ifdef USE_POSIX_THREAD */
