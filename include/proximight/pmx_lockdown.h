/*
 * pmx_lockdown.h — the "hard-wired lockdown" kill-switch and failover.
 *
 * A proxifier that silently falls back to a DIRECT connection when the proxy
 * dies is a leak. Lockdown enforces a fail-closed posture: only the active
 * proxy endpoint(s) (and loopback) are allowed out; if the proxy path is
 * unhealthy, policy decides whether to block everything, fail over to a backup,
 * or (explicitly, loudly) fail open. NOTE: the fail-over-to-a-backup path is not
 * built yet and currently blocks like fail-closed — see PMX_LOCKDOWN_FAIL_BACKUP.
 *
 * The controller is pure state-machine logic with hysteresis; the actual
 * packet-blocking is delegated to a pmx_firewall backend (WFP on Windows, pf on
 * macOS, or a stub that only tracks state).
 */
#ifndef PROXIMIGHT_PMX_LOCKDOWN_H
#define PROXIMIGHT_PMX_LOCKDOWN_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef enum pmx_lockdown_mode {
    PMX_LOCKDOWN_OFF = 0,   /* no enforcement                                */
    PMX_LOCKDOWN_FAIL_CLOSED, /* proxy down => block ALL other egress        */
    /* Intended: promote a backup, block if none. ACTUALLY: identical to
     * FAIL_CLOSED — it engages the firewall and reports PMX_LD_FAILING_OVER, but
     * nothing anywhere promotes a backup (redundancy chains don't select on
     * health either; see pmx_chain.h). Safe, since it blocks rather than leaking,
     * but it does not yet deliver continuity. */
    PMX_LOCKDOWN_FAIL_BACKUP,
    PMX_LOCKDOWN_FAIL_OPEN,   /* proxy down => allow direct (leaky; explicit)  */
    PMX_LOCKDOWN_MODE__COUNT
} pmx_lockdown_mode;

typedef struct pmx_lockdown_policy {
    pmx_lockdown_mode mode;
    bool block_until_verified; /* block egress at startup until proxy proven up */
    bool block_dns_leak;       /* force DNS through the tunnel / block :53 out   */
    bool block_ipv6;           /* block IPv6 egress (common leak vector)         */
    int health_interval_ms;    /* how often the watcher probes the proxy path    */
    int failures_before_trip;  /* consecutive failures to trip lockdown          */
    int successes_before_restore; /* consecutive successes to restore normal     */
} pmx_lockdown_policy;

/* Sensible, safety-first defaults: fail-closed, DNS+IPv6 leak protection on. */
void pmx_lockdown_policy_defaults(pmx_lockdown_policy *out);
const char *pmx_lockdown_mode_str(pmx_lockdown_mode m);

/* ---- firewall backend (pluggable enforcement) -------------------------- */

/* Room for the active proxies, every hop of a chain, and the VPN endpoints —
 * the tunnel's own endpoint MUST stay reachable or arming lockdown would block
 * the handshake that brings it up. */
#define PMX_MAX_ALLOWLIST 32

typedef struct pmx_fw_endpoint {
    char host[PMX_MAX_HOST];
    pmx_port port;
} pmx_fw_endpoint;

typedef struct pmx_firewall pmx_firewall;
struct pmx_firewall {
    const char *name;
    void *impl;

    /* Install a default-deny posture that permits only the given endpoints
     * (plus loopback). Idempotent; re-engage updates the allowlist. */
    pmx_status (*engage)(pmx_firewall *self, const pmx_fw_endpoint *allow,
                         size_t allow_count, const pmx_lockdown_policy *policy);
    /* Remove all ProxiMight firewall rules, restoring normal connectivity. */
    pmx_status (*disengage)(pmx_firewall *self);
    bool (*is_engaged)(pmx_firewall *self);
    bool (*requires_privilege)(pmx_firewall *self); /* needs admin/root? */
    void (*destroy)(pmx_firewall *self);
};

/* A no-op firewall that only records engaged/allowlist state and logs — used by
 * the stub redirection backend so the whole lockdown pipeline is exercisable. */
pmx_firewall *pmx_firewall_stub_create(void);

/* The best real firewall for this platform, or the stub if none is wired. */
pmx_firewall *pmx_firewall_platform_create(void);

/* ---- lockdown controller ---------------------------------------------- */

typedef enum pmx_lockdown_state {
    PMX_LD_INACTIVE = 0,     /* lockdown off or not started            */
    PMX_LD_ARMED_HEALTHY,    /* watching; proxy path healthy           */
    PMX_LD_TRIPPED_BLOCKING, /* proxy down; egress blocked (fail-closed) */
    /* Reached only by FAIL_BACKUP. Egress IS blocked, exactly as in
     * TRIPPED_BLOCKING; no backup is actually being tried. */
    PMX_LD_FAILING_OVER,
    PMX_LD_FAILED_OPEN,      /* proxy down; allowing direct (explicit) */
    PMX_LD_STATE__COUNT
} pmx_lockdown_state;

typedef struct pmx_lockdown pmx_lockdown;

/* Borrows `fw` (does not take ownership). Copies the policy. */
pmx_lockdown *pmx_lockdown_create(const pmx_lockdown_policy *policy,
                                  pmx_firewall *fw);
void pmx_lockdown_destroy(pmx_lockdown *ld);

void pmx_lockdown_set_policy(pmx_lockdown *ld, const pmx_lockdown_policy *policy);

/* Set the endpoints that stay reachable while locked down (the active proxy /
 * chain hops). Re-applied on the next engage. */
void pmx_lockdown_set_allowlist(pmx_lockdown *ld, const pmx_fw_endpoint *eps,
                                size_t count);

/* Begin/stop enforcement. arm() applies block_until_verified immediately. */
pmx_status pmx_lockdown_arm(pmx_lockdown *ld);
pmx_status pmx_lockdown_disarm(pmx_lockdown *ld);

/*
 * Feed one health observation of the active proxy path. Drives the hysteresis
 * state machine and, on a state change, engages/disengages the firewall.
 * Returns PMX_OK; sets *changed (optional) true if the state transitioned.
 */
pmx_status pmx_lockdown_on_health(pmx_lockdown *ld, bool healthy, bool *changed);

pmx_lockdown_state pmx_lockdown_get_state(const pmx_lockdown *ld);
const char *pmx_lockdown_state_str(pmx_lockdown_state s);

/* Introspection for the GUI status panel. */
int pmx_lockdown_consecutive_failures(const pmx_lockdown *ld);
int pmx_lockdown_consecutive_successes(const pmx_lockdown *ld);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_LOCKDOWN_H */
