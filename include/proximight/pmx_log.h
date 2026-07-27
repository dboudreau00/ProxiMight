/*
 * pmx_log.h — thread-safe leveled logging with a pluggable sink.
 *
 * The GUI installs a sink so log lines also appear in the in-app log view.
 * Rule: proxy hosts/ports/labels are fine to log; usernames and passwords are
 * NOT. Callers must never pass a credential to pmx_log*.
 */
#ifndef PROXIMIGHT_PMX_LOG_H
#define PROXIMIGHT_PMX_LOG_H

#include "proximight/pmx_types.h"
#include "proximight/pmx_error.h"
#include <stdarg.h>

PMX_BEGIN_DECLS

typedef enum pmx_log_level {
    PMX_LOG_TRACE = 0,
    PMX_LOG_DEBUG,
    PMX_LOG_INFO,
    PMX_LOG_WARN,
    PMX_LOG_ERROR,
    PMX_LOG_OFF
} pmx_log_level;

/* Sink receives already-formatted lines (no trailing newline). */
typedef void (*pmx_log_sink_fn)(void *user, pmx_log_level level, uint64_t ts_ms,
                                const char *line);

/* Initialize logging. `file_path` may be NULL to skip file output. Safe to
 * call once at startup; idempotent-ish (re-init closes the previous file). */
pmx_status pmx_log_init(const char *file_path, pmx_log_level min_level);
void pmx_log_shutdown(void);

void pmx_log_set_level(pmx_log_level min_level);
pmx_log_level pmx_log_get_level(void);

/* Register/replace the secondary sink (e.g. the GUI log panel). Pass NULL fn
 * to remove. Thread-safe.
 *
 * LIFETIME RULE: pmx_logv captures (fn, user) under the log mutex but calls the
 * sink OUTSIDE it, so unregistering does NOT wait for a call already in flight.
 * Passing NULL is therefore not enough to make `user` safe to free — you must
 * first ensure no other thread can still be logging (join them). Concretely:
 * tear down anything that owns worker threads BEFORE freeing whatever `user`
 * points at. See the shutdown ordering in gui_main.c. */
void pmx_log_set_sink(pmx_log_sink_fn fn, void *user);

void pmx_log(pmx_log_level level, const char *fmt, ...) PMX_PRINTF(2, 3);
void pmx_logv(pmx_log_level level, const char *fmt, va_list ap);

const char *pmx_log_level_str(pmx_log_level level);

#define PMX_LOGT(...) pmx_log(PMX_LOG_TRACE, __VA_ARGS__)
#define PMX_LOGD(...) pmx_log(PMX_LOG_DEBUG, __VA_ARGS__)
#define PMX_LOGI(...) pmx_log(PMX_LOG_INFO, __VA_ARGS__)
#define PMX_LOGW(...) pmx_log(PMX_LOG_WARN, __VA_ARGS__)
#define PMX_LOGE(...) pmx_log(PMX_LOG_ERROR, __VA_ARGS__)

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_LOG_H */
