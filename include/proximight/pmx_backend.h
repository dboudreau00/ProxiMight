/*
 * pmx_backend.h — the pluggable traffic-redirection backend contract.
 *
 * A backend observes new outbound connections ("flows"), reports each to the
 * engine (which resolves a decision from the active profile's rules), and then
 * enforces that decision (direct / via proxy / block).
 *
 * Backends:
 *   - stub      : always available; optionally fabricates demo traffic so the
 *                 whole pipeline (rules -> decision -> connection log) is live
 *                 without touching the OS network stack. caps.real == false.
 *   - windows   : WinDivert/Wintun user-space redirection (scaffolded).
 *   - macos     : pf + utun (scaffolded).
 */
#ifndef PROXIMIGHT_PMX_BACKEND_H
#define PROXIMIGHT_PMX_BACKEND_H

#include "proximight/pmx_rule.h" /* pmx_target_kind */
#include "proximight/pmx_proxy.h"

PMX_BEGIN_DECLS

/* An intercepted (or simulated) outbound connection. */
typedef struct pmx_flow {
    uint64_t flow_id;
    char app_name[PMX_MAX_NAME]; /* "chrome.exe"        */
    char app_path[PMX_MAX_PATH]; /* full image path     */
    uint32_t pid;
    char dst_host[PMX_MAX_HOST];
    pmx_port dst_port;
    bool udp;
    uint64_t created_ms;
} pmx_flow;

typedef enum pmx_verdict {
    PMX_VERDICT_DIRECT = 0,
    PMX_VERDICT_PROXY,
    PMX_VERDICT_BLOCK,
    PMX_VERDICT__COUNT
} pmx_verdict;

const char *pmx_verdict_str(pmx_verdict v);

/* The resolved outcome for a flow. */
typedef struct pmx_decision {
    pmx_verdict verdict;
    pmx_target_kind target_kind;
    pmx_id target_id;               /* proxy/chain id when verdict==PROXY */
    char via_label[PMX_MAX_LABEL];  /* proxy/chain label, for display     */
    char rule_name[PMX_MAX_NAME];   /* the rule that decided (or "Default")*/

    /* The concrete proxy chain to hand to the relay when verdict == PROXY, in
     * traversal order. A redirection backend runs on its own thread and must
     * not reach into the profile, so the resolved endpoints travel with the
     * decision.
     *
     * via_count == 0 means the target could not be fully resolved (a hop is
     * missing or disabled). Backends must then FAIL CLOSED — proxying through
     * fewer hops than the user asked for misrepresents their protection, which
     * is worse than not proxying at all. via_hop_count is what the target asked
     * for, so the refusal can say why. */
    pmx_proxy via_chain[PMX_MAX_CHAIN_HOPS];
    size_t via_count;
    size_t via_hop_count;
} pmx_decision;

typedef struct pmx_backend_caps {
    bool per_app;    /* can attribute a connection to a process   */
    bool can_block;  /* can enforce BLOCK                         */
    bool killswitch; /* cooperates with a firewall for lockdown   */
    bool real;       /* true redirection vs a simulation          */

    /* True when `flow.dst_host` can carry a host NAME. When false the backend
     * only ever reports a numeric IP literal, because that is all the OS hands
     * it — the application resolved the name itself before connecting.
     *
     * This matters a great deal for rules: `host_pattern` is globbed against
     * dst_host, so a name pattern like "*.example.com" can NEVER match on a
     * backend with host_names == false. It is not a small display detail, it
     * silently disables the rule. The GUI warns when a rule's host pattern
     * needs names the active backend cannot supply.
     *
     * (The stub sets this true — it fabricates named demo traffic — which is
     * exactly why name-based rules looked like they worked for so long.) */
    bool host_names;
} pmx_backend_caps;

typedef struct pmx_backend_config {
    bool demo_traffic;    /* stub only: generate synthetic flows      */
    int demo_interval_ms; /* spacing between synthetic flows          */

    /* A backend may be able to BLOCK before it can PROXY (that is exactly the
     * current state of the Windows backend). When a rule says PROXY and the
     * backend cannot redirect yet, this decides whether the connection is
     * blocked (fail closed — no silent leak) or allowed out directly
     * (convenient, leaky). Defaults to true: fail closed. */
    bool block_when_cannot_proxy;
} pmx_backend_config;

void pmx_backend_config_defaults(pmx_backend_config *cfg);

/* Called by a backend for every new flow it sees. */
typedef void (*pmx_flow_cb)(void *user, const pmx_flow *flow);

/*
 * Ask for a verdict *synchronously*. A redirection backend must decide whether
 * to allow, block, or divert a connection at the moment the OS reports it —
 * it cannot wait for the next engine pump. Backends may call this from their
 * own thread; the engine answers from a lock-protected snapshot of the profile,
 * so the live profile stays single-threaded and lock-free.
 */
typedef void (*pmx_decide_fn)(void *user, const pmx_flow *flow,
                              pmx_decision *out);

typedef struct pmx_backend pmx_backend;
struct pmx_backend {
    const char *name;
    void *impl;
    pmx_backend_caps caps;

    pmx_status (*start)(pmx_backend *self, const pmx_backend_config *cfg);
    pmx_status (*stop)(pmx_backend *self);
    bool (*is_active)(pmx_backend *self);

    void (*set_flow_cb)(pmx_backend *self, pmx_flow_cb cb, void *user);

    /* Optional — may be NULL for backends that never need an inline verdict
     * (the stub, for instance, just reports flows and lets the engine resolve
     * them on its pump thread). */
    void (*set_decide_cb)(pmx_backend *self, pmx_decide_fn fn, void *user);

    pmx_status (*apply_decision)(pmx_backend *self, const pmx_flow *flow,
                                 const pmx_decision *decision);

    void (*destroy)(pmx_backend *self);
};

/* Factories. */
pmx_backend *pmx_backend_stub_create(void);
pmx_backend *pmx_backend_platform_create(void); /* best real backend, else stub */

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_BACKEND_H */
