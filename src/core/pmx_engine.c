#include "proximight/pmx_engine.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_log.h"

#include <stdlib.h>
#include <string.h>

#define PMX_EVENT_RING 512
/* Cap on unpumped flows. Generous for a normal frame (the pump drains fully
 * every frame) but bounded if the frame loop stalls. */
#define PMX_INBOX_MAX 4096

typedef struct flow_node {
    pmx_flow flow;
    struct flow_node *next;
} flow_node;

struct pmx_engine {
    pmx_profile profile;

    pmx_backend *backend;      /* owned */
    pmx_checker *checker;      /* owned; exposed to the GUI for manual checks */
    pmx_checker *health_check; /* owned; internal lockdown health probes       */
    pmx_lockdown *lockdown;    /* owned */
    pmx_firewall *firewall;    /* owned; lent to lockdown                       */
    pmx_vpn_runner *vpn_runner; /* owned; drives the vendor VPN clients          */

    bool running;

    /* A snapshot of `profile`, refreshed once per pump. Backends resolve
     * against this from their own threads, which keeps the live profile
     * single-threaded (and therefore lock-free) on the pump/GUI side. */
    pmx_profile snap;
    pmx_mutex *snap_mutex;

    pmx_mutex *inbox_mutex;
    flow_node *flow_head, *flow_tail;
    size_t inbox_len;       /* bounded by PMX_INBOX_MAX */
    uint64_t inbox_dropped; /* flows dropped because the inbox was full */

    pmx_conn_event events[PMX_EVENT_RING];
    size_t event_head;
    size_t event_len;

    pmx_engine_status status;

    uint64_t last_health_submit_ms;
    pmx_id health_proxy_id;

    /* Last allowlist actually pushed to lockdown, so rebuild_allowlist() can run
     * every health tick (picking up profile edits) without re-applying — and on
     * a real firewall, re-creating — identical filters each time. */
    pmx_fw_endpoint allow_applied[PMX_MAX_ALLOWLIST];
    size_t allow_applied_count;

    /* Set when a load found a profile file that exists but could not be read
     * (sealed for another user/machine, or corrupt). While set, saving is
     * refused so the working defaults never clobber the user's real file. A
     * successful load clears it. */
    bool profile_locked;
};

static void engine_bind_backend(pmx_engine *e, pmx_backend *b);
static void engine_refresh_snapshot(pmx_engine *e);

/* Push the user's checker settings to BOTH checkers — but strip the optional
 * extras from the background health watcher.
 *
 * The interactive checker is a thing the user asked for, once, by pressing Test.
 * The health watcher runs every health_interval_ms (4 s by default) for as long
 * as lockdown is armed, and handing it the same options meant enabling the
 * egress-IP check — documented as an opt-in, deliberate leak for a manual
 * check — silently turned into an HTTP GET to a third-party IP-echo service
 * roughly 900 times an hour. ICMP ping goes too: it is diagnostic colour for the
 * checker panel, it does not traverse the proxy, and the kill switch does not
 * need it. Reachability plus the proxy handshake is the whole question here.
 *
 * Both call sites go through this so the two can never drift apart again. */
static void apply_check_opts(pmx_engine *e) {
    pmx_checker_set_opts(e->checker, &e->profile.settings.check);
    pmx_check_opts hopts = e->profile.settings.check;
    hopts.measure_egress_ip = false;
    hopts.measure_ping = false;
    pmx_checker_set_opts(e->health_check, &hopts);
}

/* Warn about enabled rules that match on a host NAME while the active backend
 * only ever reports numeric addresses. Such a rule silently never fires: the
 * app resolved the name itself, so dst_host is an IP literal and the traffic
 * falls through to the default action while the UI still lists the rule as
 * active. Runs whenever the backend changes AND on a successful start, because
 * the capability is known as soon as the backend is set — waiting for a start
 * that may fail (WinDivert needs Administrator) would hide it exactly when the
 * user is switching to the backend that has the limitation. */
static void audit_host_name_rules(pmx_engine *e) {
    if (e == NULL) {
        return;
    }
    bool names = (e->backend == NULL) || e->backend->caps.host_names;
    const char *bname = (e->backend != NULL) ? e->backend->name : "?";
    for (size_t i = 0; i < e->profile.rule_count; i++) {
        const pmx_rule *r = &e->profile.rules[i];
        if (!r->enabled) {
            continue;
        }
        if (!names && pmx_host_pattern_needs_names(r->host_pattern)) {
            PMX_LOGW("Rule '%s' matches on a host NAME, but backend '%s' only "
                     "reports numeric addresses — this rule will NEVER match. "
                     "Use IP patterns (e.g. 10.*) until name capture lands.",
                     r->name, bname);
        }
        /* An unparseable port spec is matched leniently rather than rejected, so
         * it can silently under-match (a Block rule that misses) or over-match
         * (a Direct rule that shadows everything below it). The editor only
         * warns while you are looking at that rule; say it once, loudly, for the
         * whole profile. */
        if (pmx_port_spec_validate(r->port_spec) != PMX_OK) {
            PMX_LOGW("Rule '%s' has an invalid port spec (\"%s\") — it will be "
                     "matched loosely and may catch more or fewer ports than you "
                     "expect. Fix it to e.g. 80,443,8000-8080.",
                     r->name, r->port_spec);
        }
    }
}

/* ---- flow inbox (called from the backend thread) ----------------------- */

static void engine_on_flow(void *user, const pmx_flow *flow) {
    pmx_engine *e = (pmx_engine *)user;

    /* Bounded, like the event ring next door. The backend thread enqueues one
     * node per intercepted connect; the pump drains them once per GUI FRAME. If
     * the frame loop stalls — dragging the window puts Win32 in a modal
     * move/size loop, so glfwPollEvents does not return — a connect storm
     * (a port scan, a reconnect loop) grew this list without limit: ~1.4 KB per
     * node, ~92 MB for a single full-range scan. Dropping the newest flow costs
     * a log row; it never changes a verdict, because backends that must gate a
     * connection use pmx_engine_decide() inline rather than this queue. */
    pmx_mutex_lock(e->inbox_mutex);
    if (e->inbox_len >= PMX_INBOX_MAX) {
        e->inbox_dropped++;
        /* Say it out loud the first time and then at decade boundaries: a
         * counter nobody looks at is the same as dropping them silently, and
         * the connection log is now incomplete. Rate-limited because this runs
         * on the backend thread during exactly the storm that caused it. */
        bool announce = (e->inbox_dropped == 1) || (e->inbox_dropped % 1000 == 0);
        uint64_t n = e->inbox_dropped;
        pmx_mutex_unlock(e->inbox_mutex);
        if (announce) {
            PMX_LOGW("Connection log is behind: %llu flow(s) dropped because the "
                     "engine could not keep up. Verdicts are unaffected (they are "
                     "decided inline), but the Connections view is incomplete.",
                     (unsigned long long)n);
        }
        return;
    }
    pmx_mutex_unlock(e->inbox_mutex);

    flow_node *n = (flow_node *)calloc(1, sizeof(*n));
    if (n == NULL) {
        return;
    }
    n->flow = *flow;
    pmx_mutex_lock(e->inbox_mutex);
    if (e->flow_tail != NULL) {
        e->flow_tail->next = n;
    } else {
        e->flow_head = n;
    }
    e->flow_tail = n;
    e->inbox_len++;
    pmx_mutex_unlock(e->inbox_mutex);
}

static flow_node *inbox_pop(pmx_engine *e) {
    pmx_mutex_lock(e->inbox_mutex);
    flow_node *n = e->flow_head;
    if (n != NULL) {
        e->flow_head = n->next;
        if (e->flow_head == NULL) {
            e->flow_tail = NULL;
        }
        if (e->inbox_len > 0) {
            e->inbox_len--;
        }
    }
    pmx_mutex_unlock(e->inbox_mutex);
    return n;
}

/* ---- lifecycle --------------------------------------------------------- */

pmx_engine *pmx_engine_create(void) {
    pmx_engine *e = (pmx_engine *)calloc(1, sizeof(*e));
    if (e == NULL) {
        return NULL;
    }
    pmx_net_init();
    pmx_profile_seed_defaults(&e->profile);

    e->inbox_mutex = pmx_mutex_create();
    pmx_profile_init(&e->snap);
    e->snap_mutex = pmx_mutex_create();
    e->firewall = pmx_firewall_platform_create();
    e->lockdown = pmx_lockdown_create(&e->profile.lockdown, e->firewall);
    e->checker = pmx_checker_create(&e->profile.settings.check);
    e->health_check = pmx_checker_create(&e->profile.settings.check);
    e->vpn_runner = pmx_vpn_runner_create();
    e->backend = pmx_backend_stub_create();

    if (e->inbox_mutex == NULL || e->snap_mutex == NULL || e->lockdown == NULL ||
        e->checker == NULL || e->health_check == NULL || e->backend == NULL) {
        pmx_engine_destroy(e);
        return NULL;
    }
    engine_bind_backend(e, e->backend);
    engine_refresh_snapshot(e);

    e->status.backend_active = false;
    pmx_strlcpy(e->status.backend_name, e->backend->name,
                sizeof(e->status.backend_name));
    e->status.backend_real = e->backend->caps.real;
    e->status.backend_host_names = e->backend->caps.host_names;
    e->status.backend_can_block = e->backend->caps.can_block;
    e->status.lockdown_state = PMX_LD_INACTIVE;
    PMX_LOGI("Engine created (backend '%s', firewall '%s')", e->backend->name,
             e->firewall ? e->firewall->name : "none");
    return e;
}

void pmx_engine_destroy(pmx_engine *e) {
    if (e == NULL) {
        return;
    }
    if (e->running) {
        pmx_engine_stop(e);
    }
    if (e->backend != NULL) {
        e->backend->destroy(e->backend);
    }
    pmx_checker_destroy(e->checker);
    pmx_checker_destroy(e->health_check);
    pmx_vpn_runner_destroy(e->vpn_runner);
    pmx_lockdown_destroy(e->lockdown);
    if (e->firewall != NULL) {
        e->firewall->destroy(e->firewall);
    }
    flow_node *n = e->flow_head;
    while (n != NULL) {
        flow_node *nx = n->next;
        free(n);
        n = nx;
    }
    pmx_mutex_destroy(e->inbox_mutex);
    pmx_mutex_destroy(e->snap_mutex);
    pmx_profile_free(&e->snap);
    pmx_profile_free(&e->profile);
    pmx_net_shutdown();
    free(e);
}

pmx_profile *pmx_engine_profile(pmx_engine *e) { return e ? &e->profile : NULL; }

pmx_status pmx_engine_load_profile(pmx_engine *e, const char *path) {
    if (e == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (e->running) {
        return PMX_ERR_STATE;
    }
    pmx_profile tmp;
    pmx_profile_init(&tmp);
    pmx_status st = pmx_profile_load(&tmp, path);
    if (st != PMX_OK) {
        pmx_profile_free(&tmp);
        /* PMX_ERR_IO means "no file" (a clean first run). Any other failure
         * means a file is there but unreadable — lock saves so we don't
         * overwrite it with the seeded defaults we're falling back to. */
        e->profile_locked = (st != PMX_ERR_IO);
        if (e->profile_locked) {
            PMX_LOGW("Refusing to overwrite the existing profile at %s until it "
                     "can be read; saving is disabled this session.",
                     path);
        }
        return st;
    }
    pmx_profile_free(&e->profile);
    e->profile = tmp; /* move ownership of the arrays */
    e->profile_locked = false;
    pmx_lockdown_set_policy(e->lockdown, &e->profile.lockdown);
    apply_check_opts(e);
    engine_refresh_snapshot(e);
    return PMX_OK;
}

pmx_status pmx_engine_save_profile(pmx_engine *e, const char *path) {
    if (e == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (e->profile_locked) {
        PMX_LOGW("Not saving: an existing profile at %s could not be read; "
                 "overwriting it would discard it.",
                 path);
        return PMX_ERR_STATE;
    }
    pmx_status st = pmx_profile_save(&e->profile, path);
    if (st == PMX_OK) {
        pmx_strlcpy(e->profile.path, path, sizeof(e->profile.path));
    }
    return st;
}

/* ---- resolution -------------------------------------------------------- */

pmx_decision pmx_resolve_with_profile(const pmx_profile *pf,
                                      const pmx_conn_query *q) {
    pmx_decision d;
    memset(&d, 0, sizeof(d));
    d.verdict = PMX_VERDICT_DIRECT;
    d.target_kind = PMX_TARGET_NONE;
    pmx_strlcpy(d.via_label, "\xE2\x80\x94", sizeof(d.via_label));
    pmx_strlcpy(d.rule_name, "Default", sizeof(d.rule_name));

    if (pf == NULL || q == NULL) {
        return d;
    }

    const pmx_rule *chosen = NULL;
    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].enabled && pmx_rule_matches(&pf->rules[i], q)) {
            chosen = &pf->rules[i];
            break;
        }
    }
    if (chosen == NULL) {
        chosen = &pf->default_rule;
    }
    pmx_strlcpy(d.rule_name, chosen->name, sizeof(d.rule_name));

    switch (chosen->action) {
    case PMX_ACTION_DIRECT:
        d.verdict = PMX_VERDICT_DIRECT;
        break;
    case PMX_ACTION_BLOCK:
        d.verdict = PMX_VERDICT_BLOCK;
        break;
    case PMX_ACTION_PROXY: {
        d.verdict = PMX_VERDICT_PROXY;
        d.target_kind = chosen->target_kind;
        d.target_id = chosen->target_id;
        pmx_profile_target_label(pf, chosen->target_kind, chosen->target_id,
                                 d.via_label, sizeof(d.via_label));

        /* Resolve the concrete endpoints for the redirection backend. */
        if (chosen->target_kind == PMX_TARGET_PROXY) {
            const pmx_proxy *p = pmx_profile_find_proxy_c(pf, chosen->target_id);
            d.via_hop_count = 1;
            if (p != NULL && p->enabled) {
                d.via_chain[0] = *p;
                d.via_count = 1;
            }
        } else if (chosen->target_kind == PMX_TARGET_CHAIN) {
            const pmx_chain *c = pmx_profile_find_chain_c(pf, chosen->target_id);
            if (c != NULL && c->enabled && c->hop_count > 0) {
                d.via_hop_count = c->hop_count;
                size_t n = 0;
                for (size_t i = 0; i < c->hop_count && i < PMX_MAX_CHAIN_HOPS;
                     i++) {
                    const pmx_proxy *hp =
                        pmx_profile_find_proxy_c(pf, c->hops[i]);
                    if (hp == NULL || !hp->enabled) {
                        n = 0; /* all or nothing — never under-proxy */
                        break;
                    }
                    d.via_chain[n++] = *hp;
                }
                d.via_count = n;
                /* A redundancy chain is a set of alternatives, not a path, so
                 * only its first reachable hop should be traversed. */
                if (c->mode == PMX_CHAIN_REDUNDANCY && d.via_count > 1) {
                    d.via_count = 1;
                    d.via_hop_count = 1;
                }
            }
        }
        break;
    }
    default:
        break;
    }
    return d;
}

pmx_decision pmx_engine_resolve(pmx_engine *e, const pmx_conn_query *q) {
    return pmx_resolve_with_profile(e ? &e->profile : NULL, q);
}

/* Publish the current profile so other threads can resolve against it. */
static void engine_refresh_snapshot(pmx_engine *e) {
    if (e == NULL || e->snap_mutex == NULL) {
        return;
    }
    pmx_mutex_lock(e->snap_mutex);
    /* pmx_profile_copy copies proxies -> rules -> chains -> vpns and bails on
     * the first failed realloc, so ignoring the status could publish a snapshot
     * whose arrays come from two different generations (new proxies, old rules)
     * and enforce that mixture until a later pump succeeded. Keeping the
     * previous CONSISTENT snapshot is the safe failure. */
    pmx_status cst = pmx_profile_copy(&e->snap, &e->profile);
    pmx_mutex_unlock(e->snap_mutex);
    if (cst != PMX_OK) {
        PMX_LOGE("Could not publish a rule snapshot (%s); still enforcing the "
                 "previous one. Edits will not take effect until this clears.",
                 pmx_status_str(cst));
    }
}

void pmx_engine_decide(pmx_engine *e, const pmx_flow *flow, pmx_decision *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->verdict = PMX_VERDICT_DIRECT;
    out->target_kind = PMX_TARGET_NONE;
    pmx_strlcpy(out->via_label, "\xE2\x80\x94", sizeof(out->via_label));
    pmx_strlcpy(out->rule_name, "Default", sizeof(out->rule_name));
    if (e == NULL || flow == NULL || e->snap_mutex == NULL) {
        return;
    }

    pmx_conn_query q;
    q.app_name = flow->app_name;
    q.app_path = flow->app_path;
    q.host = flow->dst_host;
    q.port = flow->dst_port;

    pmx_mutex_lock(e->snap_mutex);
    *out = pmx_resolve_with_profile(&e->snap, &q);
    pmx_mutex_unlock(e->snap_mutex);
}

/* Trampoline handed to backends via set_decide_cb. */
static void engine_decide_cb(void *user, const pmx_flow *flow, pmx_decision *out) {
    pmx_engine_decide((pmx_engine *)user, flow, out);
}

/* Attach both callbacks to a backend (set_decide_cb is optional). */
static void engine_bind_backend(pmx_engine *e, pmx_backend *b) {
    if (b == NULL) {
        return;
    }
    if (b->set_flow_cb != NULL) {
        b->set_flow_cb(b, engine_on_flow, e);
    }
    if (b->set_decide_cb != NULL) {
        b->set_decide_cb(b, engine_decide_cb, e);
    }
}

/* ---- event ring -------------------------------------------------------- */

static void record_event(pmx_engine *e, const pmx_flow *f, const pmx_decision *d) {
    size_t idx;
    if (e->event_len < PMX_EVENT_RING) {
        idx = (e->event_head + e->event_len) % PMX_EVENT_RING;
        e->event_len++;
    } else {
        idx = e->event_head;
        e->event_head = (e->event_head + 1) % PMX_EVENT_RING;
    }
    pmx_conn_event *ev = &e->events[idx];
    memset(ev, 0, sizeof(*ev));
    ev->flow_id = f->flow_id;
    ev->ts_ms = f->created_ms;
    pmx_strlcpy(ev->app_name, f->app_name, sizeof(ev->app_name));
    pmx_strlcpy(ev->host, f->dst_host, sizeof(ev->host));
    ev->port = f->dst_port;
    ev->verdict = d->verdict;
    pmx_strlcpy(ev->via_label, d->via_label, sizeof(ev->via_label));
    pmx_strlcpy(ev->rule_name, d->rule_name, sizeof(ev->rule_name));
}

size_t pmx_engine_recent_events(pmx_engine *e, pmx_conn_event *out, size_t max) {
    if (e == NULL || out == NULL || max == 0) {
        return 0;
    }
    size_t n = e->event_len < max ? e->event_len : max;
    size_t start = e->event_len - n;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (e->event_head + start + i) % PMX_EVENT_RING;
        out[i] = e->events[idx];
    }
    return n;
}

void pmx_engine_clear_events(pmx_engine *e) {
    if (e != NULL) {
        e->event_head = 0;
        e->event_len = 0;
    }
}

/* ---- lifecycle: start/stop/pump --------------------------------------- */

/* Recompute the firewall allowlist and pick the proxy the health watcher probes.
 *
 * Called from pmx_engine_start AND from the pump's health tick, because the user
 * can edit the profile while the engine runs. Doing it only once at start left
 * two holes: a VPN enabled after Start never reached the allowlist (so arming
 * lockdown blocked the very tunnel the allowlist exists to protect), and if the
 * probed proxy was deleted or disabled the watcher went silent — no probe, no
 * pmx_lockdown_on_health call, so lockdown sat on its last verdict, usually
 * "Armed — healthy", watching a proxy that no longer existed.
 *
 * The allowlist is only pushed down when it actually CHANGED: set_allowlist
 * re-applies the firewall while engaged, and doing that every tick would thrash
 * real WFP filters. */
static void rebuild_allowlist(pmx_engine *e) {
    pmx_fw_endpoint eps[PMX_MAX_ALLOWLIST];
    size_t n = 0;
    for (size_t i = 0; i < e->profile.proxy_count &&
                       n < PMX_ARRAY_LEN(eps);
         i++) {
        if (e->profile.proxies[i].enabled) {
            pmx_strlcpy(eps[n].host, e->profile.proxies[i].host,
                        sizeof(eps[n].host));
            eps[n].port = e->profile.proxies[i].port;
            n++;
        }
    }
    /* The VPN endpoint has to stay reachable while locked down, or the tunnel
     * could never be (re)established — a kill switch that blocks its own tunnel
     * is just an outage. */
    for (size_t i = 0; i < e->profile.vpn_count && n < PMX_ARRAY_LEN(eps); i++) {
        const pmx_vpn *v = &e->profile.vpns[i];
        if (!v->enabled) {
            continue;
        }
        for (size_t j = 0; j < v->endpoint_count && n < PMX_ARRAY_LEN(eps); j++) {
            pmx_strlcpy(eps[n].host, v->endpoints[j].host, sizeof(eps[n].host));
            eps[n].port = v->endpoints[j].port;
            n++;
        }
    }
    if (n != e->allow_applied_count ||
        (n > 0 && memcmp(eps, e->allow_applied, n * sizeof(eps[0])) != 0)) {
        pmx_lockdown_set_allowlist(e->lockdown, eps, n);
        memcpy(e->allow_applied, eps, n * sizeof(eps[0]));
        e->allow_applied_count = n;
    }

    /* Track which proxy the health watcher will probe (first enabled one). */
    e->health_proxy_id = PMX_ID_NONE;
    for (size_t i = 0; i < e->profile.proxy_count; i++) {
        if (e->profile.proxies[i].enabled) {
            e->health_proxy_id = e->profile.proxies[i].id;
            break;
        }
    }
}

bool pmx_engine_is_running(pmx_engine *e) { return e && e->running; }

pmx_status pmx_engine_start(pmx_engine *e) {
    if (e == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (e->running) {
        return PMX_OK;
    }
    apply_check_opts(e);

    pmx_backend_config cfg;
    pmx_backend_config_defaults(&cfg);
    cfg.demo_traffic = e->profile.settings.demo_traffic;
    cfg.demo_interval_ms = e->profile.settings.demo_interval_ms > 0
                               ? e->profile.settings.demo_interval_ms
                               : 1500;
    /* Tie "what if we can't proxy yet" to the user's leak stance: anything but
     * an explicit fail-open means block rather than leak direct. */
    cfg.block_when_cannot_proxy =
        (e->profile.lockdown.mode != PMX_LOCKDOWN_FAIL_OPEN);

    pmx_status st = e->backend->start(e->backend, &cfg);
    if (st != PMX_OK) {
        PMX_LOGE("Backend '%s' failed to start: %s", e->backend->name,
                 pmx_status_str(st));
        return st;
    }

    rebuild_allowlist(e);
    pmx_lockdown_set_policy(e->lockdown, &e->profile.lockdown);
    pmx_lockdown_arm(e->lockdown);

    e->running = true;
    e->status.running = true;
    e->status.backend_active = true;
    e->status.backend_real = e->backend->caps.real;
    e->status.backend_can_block = e->backend->caps.can_block;
    e->status.backend_host_names = e->backend->caps.host_names;
    pmx_strlcpy(e->status.backend_name, e->backend->name,
                sizeof(e->status.backend_name));
    e->last_health_submit_ms = 0;
    PMX_LOGI("Engine started");
    audit_host_name_rules(e);
    return PMX_OK;
}

pmx_status pmx_engine_stop(pmx_engine *e) {
    if (e == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (!e->running) {
        return PMX_OK;
    }
    e->backend->stop(e->backend);
    pmx_lockdown_disarm(e->lockdown);
    e->running = false;
    e->status.running = false;
    e->status.backend_active = false;
    e->status.lockdown_state = PMX_LD_INACTIVE;
    PMX_LOGI("Engine stopped");
    return PMX_OK;
}

void pmx_engine_pump(pmx_engine *e) {
    if (e == NULL) {
        return;
    }

    /* 0) Publish the profile for backend threads that need inline verdicts.
     *    Profiles are small, so copying once per frame is cheaper than trying
     *    to track every in-place edit the GUI makes. */
    engine_refresh_snapshot(e);

    /* Notice a VPN client that exited on its own. */
    pmx_vpn_runner_poll(e->vpn_runner);

    /* 1) Resolve + record + enforce every queued flow. */
    flow_node *n;
    while ((n = inbox_pop(e)) != NULL) {
        pmx_conn_query q;
        q.app_name = n->flow.app_name;
        q.app_path = n->flow.app_path;
        q.host = n->flow.dst_host;
        q.port = n->flow.dst_port;
        pmx_decision d = pmx_engine_resolve(e, &q);

        record_event(e, &n->flow, &d);
        e->status.flows_total++;
        switch (d.verdict) {
        case PMX_VERDICT_PROXY:  e->status.flows_proxied++; break;
        case PMX_VERDICT_DIRECT: e->status.flows_direct++;  break;
        case PMX_VERDICT_BLOCK:  e->status.flows_blocked++; break;
        default: break;
        }
        if (e->backend->apply_decision != NULL) {
            e->backend->apply_decision(e->backend, &n->flow, &d);
        }
        free(n);
    }

    if (!e->running) {
        return;
    }

    /* 2) Lockdown health watcher: periodically probe the active proxy. */
    if (e->profile.lockdown.mode != PMX_LOCKDOWN_OFF &&
        e->health_proxy_id != PMX_ID_NONE) {
        uint64_t now = pmx_now_ms();
        int interval = e->profile.lockdown.health_interval_ms > 0
                           ? e->profile.lockdown.health_interval_ms
                           : 4000;
        if (now - e->last_health_submit_ms >= (uint64_t)interval &&
            pmx_checker_pending(e->health_check) == 0) {
            /* Pick up profile edits made since Start: a VPN that needs
             * allowlisting, or a change to which proxy we should be probing. */
            rebuild_allowlist(e);
            const pmx_proxy *hp =
                pmx_profile_find_proxy(&e->profile, e->health_proxy_id);
            e->last_health_submit_ms = now;
            if (hp != NULL) {
                pmx_checker_submit(e->health_check, hp);
            } else {
                /* No enabled proxy left to watch. Report UNHEALTHY rather than
                 * simply not probing: staying silent leaves lockdown on its last
                 * verdict — usually "Armed — healthy" — which claims a protection
                 * whose subject no longer exists. A kill switch with nothing to
                 * watch has failed, and must trip. */
                bool changed = false;
                pmx_lockdown_on_health(e->lockdown, false, &changed);
                if (changed) {
                    PMX_LOGW("[lockdown] no enabled proxy left to watch — "
                             "treating the proxy path as DOWN.");
                }
            }
        }
        pmx_check_result r;
        while (pmx_checker_poll(e->health_check, &r)) {
            bool healthy = (r.status == PMX_OK);
            bool changed = false;
            pmx_lockdown_on_health(e->lockdown, healthy, &changed);
        }
    }

    e->status.lockdown_state = pmx_lockdown_get_state(e->lockdown);
}

/* ---- introspection ----------------------------------------------------- */

void pmx_engine_get_status(pmx_engine *e, pmx_engine_status *out) {
    if (e == NULL || out == NULL) {
        return;
    }
    e->status.lockdown_state = pmx_lockdown_get_state(e->lockdown);
    pmx_mutex_lock(e->inbox_mutex);
    e->status.flows_dropped = e->inbox_dropped;
    pmx_mutex_unlock(e->inbox_mutex);
    *out = e->status;
}

pmx_checker *pmx_engine_checker(pmx_engine *e) { return e ? e->checker : NULL; }
pmx_lockdown *pmx_engine_lockdown(pmx_engine *e) { return e ? e->lockdown : NULL; }
pmx_backend *pmx_engine_backend(pmx_engine *e) { return e ? e->backend : NULL; }
pmx_vpn_runner *pmx_engine_vpn_runner(pmx_engine *e) {
    return e ? e->vpn_runner : NULL;
}

pmx_status pmx_engine_set_backend(pmx_engine *e, pmx_backend *backend) {
    if (e == NULL || backend == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (e->running) {
        return PMX_ERR_STATE;
    }
    if (e->backend != NULL) {
        e->backend->destroy(e->backend);
    }
    e->backend = backend;
    engine_bind_backend(e, e->backend);
    pmx_strlcpy(e->status.backend_name, backend->name,
                sizeof(e->status.backend_name));
    e->status.backend_real = backend->caps.real;
    e->status.backend_host_names = backend->caps.host_names;
    e->status.backend_can_block = backend->caps.can_block;
    audit_host_name_rules(e);
    return PMX_OK;
}
