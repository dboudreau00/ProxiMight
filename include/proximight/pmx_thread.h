/*
 * pmx_thread.h — tiny portable threading primitives (Win32 / pthreads).
 *
 * MSVC does not ship C11 <threads.h>, so we wrap the native APIs. Only what the
 * async proxy checker and the lockdown watcher need: a joinable thread, a
 * mutex, and a condition variable.
 */
#ifndef PROXIMIGHT_PMX_THREAD_H
#define PROXIMIGHT_PMX_THREAD_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef struct pmx_thread pmx_thread;
typedef struct pmx_mutex pmx_mutex;
typedef struct pmx_cond pmx_cond;

typedef void (*pmx_thread_fn)(void *arg);

pmx_status pmx_thread_start(pmx_thread_fn fn, void *arg, pmx_thread **out);
void pmx_thread_join(pmx_thread *t); /* joins and frees the handle */

pmx_mutex *pmx_mutex_create(void);
void pmx_mutex_destroy(pmx_mutex *m);
void pmx_mutex_lock(pmx_mutex *m);
void pmx_mutex_unlock(pmx_mutex *m);

pmx_cond *pmx_cond_create(void);
void pmx_cond_destroy(pmx_cond *c);
void pmx_cond_wait(pmx_cond *c, pmx_mutex *m);
/* Returns false on timeout, true if signaled. */
bool pmx_cond_wait_timed(pmx_cond *c, pmx_mutex *m, int timeout_ms);
void pmx_cond_signal(pmx_cond *c);
void pmx_cond_broadcast(pmx_cond *c);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_THREAD_H */
