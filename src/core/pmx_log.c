#include "proximight/pmx_log.h"
#include "proximight/pmx_net.h"    /* pmx_now_ms */
#include "proximight/pmx_thread.h" /* pmx_mutex  */

#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *g_file = NULL;
static pmx_log_level g_level = PMX_LOG_INFO;
static pmx_log_sink_fn g_sink = NULL;
static void *g_sink_user = NULL;
static pmx_mutex *g_mutex = NULL;

pmx_status pmx_log_init(const char *file_path, pmx_log_level min_level) {
    if (g_mutex == NULL) {
        g_mutex = pmx_mutex_create();
        if (g_mutex == NULL) {
            return PMX_ERR_NO_MEMORY;
        }
    }
    pmx_mutex_lock(g_mutex);
    g_level = min_level;
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    if (file_path != NULL && file_path[0] != '\0') {
        g_file = fopen(file_path, "a");
    }
    pmx_mutex_unlock(g_mutex);
    return PMX_OK;
}

void pmx_log_shutdown(void) {
    if (g_mutex != NULL) {
        pmx_mutex_lock(g_mutex);
    }
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_sink = NULL;
    g_sink_user = NULL;
    if (g_mutex != NULL) {
        pmx_mutex_unlock(g_mutex);
        pmx_mutex_destroy(g_mutex);
        g_mutex = NULL;
    }
}

void pmx_log_set_level(pmx_log_level min_level) { g_level = min_level; }
pmx_log_level pmx_log_get_level(void) { return g_level; }

void pmx_log_set_sink(pmx_log_sink_fn fn, void *user) {
    if (g_mutex != NULL) {
        pmx_mutex_lock(g_mutex);
    }
    g_sink = fn;
    g_sink_user = user;
    if (g_mutex != NULL) {
        pmx_mutex_unlock(g_mutex);
    }
}

const char *pmx_log_level_str(pmx_log_level level) {
    switch (level) {
    case PMX_LOG_TRACE: return "TRACE";
    case PMX_LOG_DEBUG: return "DEBUG";
    case PMX_LOG_INFO:  return "INFO";
    case PMX_LOG_WARN:  return "WARN";
    case PMX_LOG_ERROR: return "ERROR";
    case PMX_LOG_OFF:   return "OFF";
    }
    return "?";
}

void pmx_logv(pmx_log_level level, const char *fmt, va_list ap) {
    if (level < g_level || level == PMX_LOG_OFF) {
        return;
    }

    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    msg[sizeof(msg) - 1] = '\0';

    /* Wall-clock prefix for the file/console; the GUI sink formats its own. */
    char stamp[32];
    time_t now = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);

    uint64_t ts_ms = pmx_now_ms();

    if (g_mutex != NULL) {
        pmx_mutex_lock(g_mutex);
    }
    if (g_file != NULL) {
        fprintf(g_file, "%s [%-5s] %s\n", stamp, pmx_log_level_str(level), msg);
        fflush(g_file);
    }
    fprintf(stderr, "%s [%-5s] %s\n", stamp, pmx_log_level_str(level), msg);
    pmx_log_sink_fn sink = g_sink;
    void *user = g_sink_user;
    if (g_mutex != NULL) {
        pmx_mutex_unlock(g_mutex);
    }

    if (sink != NULL) {
        sink(user, level, ts_ms, msg);
    }
}

void pmx_log(pmx_log_level level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pmx_logv(level, fmt, ap);
    va_end(ap);
}
