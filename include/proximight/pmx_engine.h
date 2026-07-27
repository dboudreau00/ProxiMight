/*
 * pmx_engine.h — the orchestrator that ties a profile to a redirection backend,
 * the proxy checker, and the lockdown kill-switch.
 *
 * Threading model (kept deliberately simple and race-free):
 *   - The backend runs on its own thread and pushes flows into the engine's
 *     lock-protected inbox.
 *   - Everything that touches the profile (rule resolution, event recording,
 *     applying decisions, driving lockdown) happens on the caller's thread when
 *     it calls pmx_engine_pump() — typically the GUI thread, once per frame.
 *   - The checker owns a separate worker for network probes and hands results
 *     back through its own queue.
 * So the profile is only ever read/written from one thread. No profile locks.
 */
#ifndef PROXIMIGHT_PMX_ENGINE_H
#define PROXIMIGHT_PMX_ENGINE_H

#include "proximight/pmx_profile.h"
#include "proximight/pmx_backend.h"
#include "proximight/pmx_checker.h"
#include "proximight/pmx_lockdown.h"

PMX_BEGIN_DECLS

/* One entry in the connections log shown by the GUI. */
typedef struct pmx_conn_event {
    uint64_t flow_id;
    uint64_t ts_ms;
    char app_name[PMX_MAX_NAME];
    char host[PMX_MAX_HOST];
    pmx_port port;
    pmx_verdict verdict;
    char via_label[PMX_MAX_LABEL];
    char rule_name[PMX_MAX_NAME];
} pmx_conn_event;

typedef struct pmx_engine_status {
    bool running;
    bool backend_active;
    bool backend_real;
    /* Mirrors caps.host_names: false means flows only ever carry a numeric IP,
     * so rules whose host pattern needs a NAME can never match. */
    bool backend_host_names;
    /* Mirrors caps.can_block. Distinct from backend_real, and the UI must not
     * conflate them: the WinDivert backend blocks real connections for real
     * while backend_real is still false, because "real" tracks whether the
     * PROXY redirect has been proven on the wire. Telling that user they are on
     * a simulation with demo traffic is wrong in the direction that matters. */
    bool backend_can_block;
    char backend_name[PMX_MAX_LABEL];
    pmx_lockdown_state lockdown_state;
    uint64_t flows_total;
    uint64_t flows_proxied;
    uint64_t flows_direct;
    uint64_t flows_blocked;
    /* Flows the backend reported but the engine had to drop because the inbox
     * was full (the frame loop stalled). Display-only: a dropped flow never
     * changes a verdict, since gating backends decide inline via
     * pmx_engine_decide(). Non-zero means the connection LOG is incomplete. */
    uint64_t flows_dropped;
} pmx_engine_status;

typedef struct pmx_engine pmx_engine;

pmx_engine *pmx_engine_create(void);
void pmx_engine_destroy(pmx_engine *e);

/* The active, editable profile. Edit it only from the pump/GUI thread. */
pmx_profile *pmx_engine_profile(pmx_engine *e);

pmx_status pmx_engine_load_profile(pmx_engine *e, const char *path);
pmx_status pmx_engine_save_profile(pmx_engine *e, const char *path);

/* ---- rule resolution (pure; the heart of the proxifier) ---------------- */

/* Classify a query against the engine's active profile. */
pmx_decision pmx_engine_resolve(pmx_engine *e, const pmx_conn_query *q);

/* Stateless resolution against an arbitrary profile (used by unit tests). */
pmx_decision pmx_resolve_with_profile(const pmx_profile *pf,
                                      const pmx_conn_query *q);

/*
 * Thread-safe resolution for a flow, answered from the engine's snapshot of the
 * profile. Safe to call from any thread — this is what a redirection backend
 * uses to get an inline verdict. The snapshot is refreshed by pmx_engine_pump(),
 * so edits made in the GUI take effect on the next pump (one frame).
 */
void pmx_engine_decide(pmx_engine *e, const pmx_flow *flow, pmx_decision *out);

/* ---- lifecycle --------------------------------------------------------- */

bool pmx_engine_is_running(pmx_engine *e);
pmx_status pmx_engine_start(pmx_engine *e); /* start backend + arm lockdown  */
pmx_status pmx_engine_stop(pmx_engine *e);

/* Drain queued flows, resolve+record+enforce them, and service the lockdown
 * watcher. Call once per GUI frame (or on a timer for a headless front-end). */
void pmx_engine_pump(pmx_engine *e);

/* ---- introspection for the GUI ---------------------------------------- */

void pmx_engine_get_status(pmx_engine *e, pmx_engine_status *out);

/* Copy up to `max` most-recent events into out[] (chronological, newest last).
 * Returns the number copied. */
size_t pmx_engine_recent_events(pmx_engine *e, pmx_conn_event *out, size_t max);
void pmx_engine_clear_events(pmx_engine *e);

/* Sub-objects the GUI drives directly. */
pmx_checker *pmx_engine_checker(pmx_engine *e);
pmx_lockdown *pmx_engine_lockdown(pmx_engine *e);
pmx_backend *pmx_engine_backend(pmx_engine *e);
/* Tunnel control, polled by pmx_engine_pump(). */
pmx_vpn_runner *pmx_engine_vpn_runner(pmx_engine *e);

/* Swap the redirection backend (e.g. stub <-> platform). Only when stopped. */
pmx_status pmx_engine_set_backend(pmx_engine *e, pmx_backend *backend);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_ENGINE_H */
