/*
 * backend_stub.c — the default, always-available redirection backend.
 *
 * It does NOT touch the OS network stack. Instead it (optionally) fabricates
 * plausible outbound flows on a timer and reports them through the flow
 * callback, so the entire pipeline — rule resolution, decisions, the
 * connection log, the lockdown watcher — is live and demonstrable without any
 * driver, admin rights, or platform entitlement. caps.real == false.
 *
 * This file also owns the small platform-selection factories shared by every
 * build (pmx_backend_platform_create) plus a couple of enum helpers.
 */
#include "proximight/pmx_backend.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void pmx_backend_config_defaults(pmx_backend_config *cfg) {
    if (cfg == NULL) {
        return;
    }
    cfg->demo_traffic = true;
    cfg->demo_interval_ms = 1500;
    cfg->block_when_cannot_proxy = true; /* fail closed by default */
}

const char *pmx_verdict_str(pmx_verdict v) {
    switch (v) {
    case PMX_VERDICT_DIRECT: return "Direct";
    case PMX_VERDICT_PROXY:  return "Proxy";
    case PMX_VERDICT_BLOCK:  return "Block";
    case PMX_VERDICT__COUNT:  break;
    }
    return "?";
}

/* ---- demo flow source -------------------------------------------------- */

static const char *const kApps[] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "Spotify.exe", "Discord.exe",
    "curl.exe",   "steam.exe",   "slack.exe",  "Code.exe",    "thunderbird.exe",
};
static const char *const kHosts[] = {
    "example.com",      "api.github.com", "cdn.jsdelivr.net",
    "youtube.com",      "discord.com",    "10.0.0.5",
    "192.168.1.10",     "localhost",      "raw.githubusercontent.com",
    "1.1.1.1",
};
static const pmx_port kPorts[] = {443, 80, 443, 8080, 443, 22, 443, 53};

typedef struct stub_impl {
    pmx_flow_cb cb;
    void *cb_user;
    pmx_mutex *mutex;
    pmx_thread *thread;
    bool running;
    int interval_ms;
    uint64_t counter;
} stub_impl;

static bool impl_running(stub_impl *im) {
    pmx_mutex_lock(im->mutex);
    bool r = im->running;
    pmx_mutex_unlock(im->mutex);
    return r;
}

static void demo_worker(void *arg) {
    pmx_backend *self = (pmx_backend *)arg;
    stub_impl *im = (stub_impl *)self->impl;
    while (impl_running(im)) {
        int slept = 0;
        while (impl_running(im) && slept < im->interval_ms) {
            pmx_sleep_ms(50);
            slept += 50;
        }
        if (!impl_running(im)) {
            break;
        }
        uint64_t i = im->counter++;
        pmx_flow f;
        memset(&f, 0, sizeof(f));
        f.flow_id = i + 1;
        pmx_strlcpy(f.app_name, kApps[i % (sizeof(kApps) / sizeof(kApps[0]))],
                    sizeof(f.app_name));
        snprintf(f.app_path, sizeof(f.app_path), "C:\\Apps\\%s", f.app_name);
        pmx_strlcpy(f.dst_host,
                    kHosts[(i * 3 + 1) % (sizeof(kHosts) / sizeof(kHosts[0]))],
                    sizeof(f.dst_host));
        f.dst_port = kPorts[i % (sizeof(kPorts) / sizeof(kPorts[0]))];
        f.pid = (uint32_t)(1000 + (i % 50));
        f.udp = (f.dst_port == 53);
        f.created_ms = pmx_now_ms();

        pmx_mutex_lock(im->mutex);
        pmx_flow_cb cb = im->cb;
        void *user = im->cb_user;
        pmx_mutex_unlock(im->mutex);
        if (cb != NULL) {
            cb(user, &f);
        }
    }
}

/* ---- vtable ------------------------------------------------------------ */

static pmx_status stub_start(pmx_backend *self, const pmx_backend_config *cfg) {
    stub_impl *im = (stub_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    if (im->running) {
        pmx_mutex_unlock(im->mutex);
        return PMX_OK;
    }
    im->running = true;
    im->interval_ms = (cfg && cfg->demo_interval_ms > 0) ? cfg->demo_interval_ms
                                                          : 1500;
    bool demo = (cfg == NULL) ? true : cfg->demo_traffic;
    pmx_mutex_unlock(im->mutex);

    PMX_LOGI("[backend:stub] started%s", demo ? " (demo traffic on)" : "");
    if (demo) {
        if (pmx_thread_start(demo_worker, self, &im->thread) != PMX_OK) {
            PMX_LOGW("[backend:stub] demo worker failed to start");
        }
    }
    return PMX_OK;
}

static pmx_status stub_stop(pmx_backend *self) {
    stub_impl *im = (stub_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    bool was = im->running;
    im->running = false;
    pmx_thread *t = im->thread;
    im->thread = NULL;
    pmx_mutex_unlock(im->mutex);
    if (t != NULL) {
        pmx_thread_join(t);
    }
    if (was) {
        PMX_LOGI("[backend:stub] stopped");
    }
    return PMX_OK;
}

static bool stub_is_active(pmx_backend *self) {
    return impl_running((stub_impl *)self->impl);
}

static void stub_set_flow_cb(pmx_backend *self, pmx_flow_cb cb, void *user) {
    stub_impl *im = (stub_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    im->cb = cb;
    im->cb_user = user;
    pmx_mutex_unlock(im->mutex);
}

static pmx_status stub_apply_decision(pmx_backend *self, const pmx_flow *flow,
                                      const pmx_decision *d) {
    (void)self;
    PMX_LOGD("[backend:stub] #%llu %s -> %s:%u => %s via %s [%s]",
             (unsigned long long)flow->flow_id, flow->app_name, flow->dst_host,
             (unsigned)flow->dst_port, pmx_verdict_str(d->verdict), d->via_label,
             d->rule_name);
    return PMX_OK;
}

static void stub_destroy(pmx_backend *self) {
    if (self == NULL) {
        return;
    }
    stub_stop(self);
    stub_impl *im = (stub_impl *)self->impl;
    if (im != NULL) {
        pmx_mutex_destroy(im->mutex);
        free(im);
    }
    free(self);
}

pmx_backend *pmx_backend_stub_create(void) {
    pmx_backend *b = (pmx_backend *)calloc(1, sizeof(*b));
    stub_impl *im = (stub_impl *)calloc(1, sizeof(*im));
    if (b == NULL || im == NULL) {
        free(b);
        free(im);
        return NULL;
    }
    im->mutex = pmx_mutex_create();
    if (im->mutex == NULL) {
        free(b);
        free(im);
        return NULL;
    }
    im->interval_ms = 1500;
    b->name = "stub";
    b->impl = im;
    b->caps.per_app = false;
    b->caps.can_block = false;
    b->caps.killswitch = false;
    b->caps.real = false;
    b->caps.host_names = true; /* demo flows carry names like "example.com" */
    b->start = stub_start;
    b->stop = stub_stop;
    b->is_active = stub_is_active;
    b->set_flow_cb = stub_set_flow_cb;
    b->apply_decision = stub_apply_decision;
    b->destroy = stub_destroy;
    return b;
}

/* ---- platform backend selection --------------------------------------- */

#if defined(PMX_PLATFORM_WINDOWS)
extern pmx_backend *pmx_backend_windivert_create(void);
#elif defined(PMX_PLATFORM_MACOS)
extern pmx_backend *pmx_backend_pf_create(void);
#endif

pmx_backend *pmx_backend_platform_create(void) {
#if defined(PMX_PLATFORM_WINDOWS)
    pmx_backend *b = pmx_backend_windivert_create();
    return b ? b : pmx_backend_stub_create();
#elif defined(PMX_PLATFORM_MACOS)
    pmx_backend *b = pmx_backend_pf_create();
    return b ? b : pmx_backend_stub_create();
#else
    return pmx_backend_stub_create();
#endif
}
