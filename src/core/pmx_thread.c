#include "proximight/pmx_thread.h"

#include <stdlib.h>

#if defined(_WIN32)
/* ------------------------------------------------------------- Windows --- */
#include <windows.h>

struct pmx_thread {
    HANDLE handle;
    pmx_thread_fn fn;
    void *arg;
};
struct pmx_mutex {
    CRITICAL_SECTION cs;
};
struct pmx_cond {
    CONDITION_VARIABLE cv;
};

static DWORD WINAPI pmx_thread_trampoline(LPVOID param) {
    pmx_thread *t = (pmx_thread *)param;
    t->fn(t->arg);
    return 0;
}

pmx_status pmx_thread_start(pmx_thread_fn fn, void *arg, pmx_thread **out) {
    if (fn == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_thread *t = (pmx_thread *)calloc(1, sizeof(*t));
    if (t == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    t->fn = fn;
    t->arg = arg;
    t->handle = CreateThread(NULL, 0, pmx_thread_trampoline, t, 0, NULL);
    if (t->handle == NULL) {
        free(t);
        return PMX_ERR_STATE;
    }
    *out = t;
    return PMX_OK;
}

void pmx_thread_join(pmx_thread *t) {
    if (t == NULL) {
        return;
    }
    WaitForSingleObject(t->handle, INFINITE);
    CloseHandle(t->handle);
    free(t);
}

pmx_mutex *pmx_mutex_create(void) {
    pmx_mutex *m = (pmx_mutex *)malloc(sizeof(*m));
    if (m != NULL) {
        InitializeCriticalSection(&m->cs);
    }
    return m;
}
void pmx_mutex_destroy(pmx_mutex *m) {
    if (m != NULL) {
        DeleteCriticalSection(&m->cs);
        free(m);
    }
}
void pmx_mutex_lock(pmx_mutex *m) { EnterCriticalSection(&m->cs); }
void pmx_mutex_unlock(pmx_mutex *m) { LeaveCriticalSection(&m->cs); }

pmx_cond *pmx_cond_create(void) {
    pmx_cond *c = (pmx_cond *)malloc(sizeof(*c));
    if (c != NULL) {
        InitializeConditionVariable(&c->cv);
    }
    return c;
}
void pmx_cond_destroy(pmx_cond *c) { free(c); }
void pmx_cond_wait(pmx_cond *c, pmx_mutex *m) {
    SleepConditionVariableCS(&c->cv, &m->cs, INFINITE);
}
bool pmx_cond_wait_timed(pmx_cond *c, pmx_mutex *m, int timeout_ms) {
    return SleepConditionVariableCS(&c->cv, &m->cs, (DWORD)timeout_ms) != 0;
}
void pmx_cond_signal(pmx_cond *c) { WakeConditionVariable(&c->cv); }
void pmx_cond_broadcast(pmx_cond *c) { WakeAllConditionVariable(&c->cv); }

#else
/* --------------------------------------------------------------- POSIX --- */
#include <pthread.h>
#include <time.h>
#include <errno.h>

struct pmx_thread {
    pthread_t thread;
    pmx_thread_fn fn;
    void *arg;
};
struct pmx_mutex {
    pthread_mutex_t m;
};
struct pmx_cond {
    pthread_cond_t c;
};

static void *pmx_thread_trampoline(void *param) {
    pmx_thread *t = (pmx_thread *)param;
    t->fn(t->arg);
    return NULL;
}

pmx_status pmx_thread_start(pmx_thread_fn fn, void *arg, pmx_thread **out) {
    if (fn == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_thread *t = (pmx_thread *)calloc(1, sizeof(*t));
    if (t == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    t->fn = fn;
    t->arg = arg;
    if (pthread_create(&t->thread, NULL, pmx_thread_trampoline, t) != 0) {
        free(t);
        return PMX_ERR_STATE;
    }
    *out = t;
    return PMX_OK;
}

void pmx_thread_join(pmx_thread *t) {
    if (t == NULL) {
        return;
    }
    pthread_join(t->thread, NULL);
    free(t);
}

pmx_mutex *pmx_mutex_create(void) {
    pmx_mutex *m = (pmx_mutex *)malloc(sizeof(*m));
    if (m != NULL) {
        pthread_mutex_init(&m->m, NULL);
    }
    return m;
}
void pmx_mutex_destroy(pmx_mutex *m) {
    if (m != NULL) {
        pthread_mutex_destroy(&m->m);
        free(m);
    }
}
void pmx_mutex_lock(pmx_mutex *m) { pthread_mutex_lock(&m->m); }
void pmx_mutex_unlock(pmx_mutex *m) { pthread_mutex_unlock(&m->m); }

pmx_cond *pmx_cond_create(void) {
    pmx_cond *c = (pmx_cond *)malloc(sizeof(*c));
    if (c != NULL) {
        pthread_cond_init(&c->c, NULL);
    }
    return c;
}
void pmx_cond_destroy(pmx_cond *c) {
    if (c != NULL) {
        pthread_cond_destroy(&c->c);
        free(c);
    }
}
void pmx_cond_wait(pmx_cond *c, pmx_mutex *m) { pthread_cond_wait(&c->c, &m->m); }

bool pmx_cond_wait_timed(pmx_cond *c, pmx_mutex *m, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    return pthread_cond_timedwait(&c->c, &m->m, &ts) == 0;
}
void pmx_cond_signal(pmx_cond *c) { pthread_cond_signal(&c->c); }
void pmx_cond_broadcast(pmx_cond *c) { pthread_cond_broadcast(&c->c); }

#endif
