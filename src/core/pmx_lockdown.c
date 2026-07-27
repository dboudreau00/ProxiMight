#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_log.h"

#include <stdlib.h>
#include <string.h>

void pmx_lockdown_policy_defaults(pmx_lockdown_policy *out) {
    if (out == NULL) {
        return;
    }
    out->mode = PMX_LOCKDOWN_FAIL_CLOSED;
    out->block_until_verified = true;
    out->block_dns_leak = true;
    out->block_ipv6 = true;
    out->health_interval_ms = 4000;
    out->failures_before_trip = 2;
    out->successes_before_restore = 2;
}

const char *pmx_lockdown_mode_str(pmx_lockdown_mode m) {
    switch (m) {
    case PMX_LOCKDOWN_OFF:         return "Off";
    case PMX_LOCKDOWN_FAIL_CLOSED: return "Fail closed";
    case PMX_LOCKDOWN_FAIL_BACKUP: return "Fail to backup";
    case PMX_LOCKDOWN_FAIL_OPEN:   return "Fail open (leaky)";
    case PMX_LOCKDOWN_MODE__COUNT: break;
    }
    return "?";
}

const char *pmx_lockdown_state_str(pmx_lockdown_state s) {
    switch (s) {
    case PMX_LD_INACTIVE:         return "Inactive";
    case PMX_LD_ARMED_HEALTHY:    return "Armed — healthy";
    case PMX_LD_TRIPPED_BLOCKING: return "Tripped — blocking";
    case PMX_LD_FAILING_OVER:     return "Failing over";
    case PMX_LD_FAILED_OPEN:      return "Failed open — leaking";
    case PMX_LD_STATE__COUNT:     break;
    }
    return "?";
}

/* ------------------------------------------------------ stub firewall ---- */

typedef struct stub_fw {
    bool engaged;
    pmx_fw_endpoint allow[PMX_MAX_ALLOWLIST];
    size_t allow_count;
} stub_fw;

static pmx_status stub_engage(pmx_firewall *self, const pmx_fw_endpoint *allow,
                              size_t allow_count, const pmx_lockdown_policy *pol) {
    stub_fw *fw = (stub_fw *)self->impl;
    fw->allow_count = 0;
    for (size_t i = 0; i < allow_count && fw->allow_count < PMX_ARRAY_LEN(fw->allow);
         i++) {
        fw->allow[fw->allow_count++] = allow[i];
    }
    fw->engaged = true;
    PMX_LOGW("[firewall:stub] ENGAGED default-deny; %zu endpoint(s) allowed%s%s",
             fw->allow_count, pol && pol->block_dns_leak ? " +dns-guard" : "",
             pol && pol->block_ipv6 ? " +ipv6-block" : "");
    for (size_t i = 0; i < fw->allow_count; i++) {
        PMX_LOGI("[firewall:stub]   allow %s:%u", fw->allow[i].host,
                 (unsigned)fw->allow[i].port);
    }
    return PMX_OK;
}

static pmx_status stub_disengage(pmx_firewall *self) {
    stub_fw *fw = (stub_fw *)self->impl;
    if (fw->engaged) {
        PMX_LOGI("[firewall:stub] DISENGAGED — normal connectivity restored");
    }
    fw->engaged = false;
    fw->allow_count = 0;
    return PMX_OK;
}

static bool stub_is_engaged(pmx_firewall *self) {
    return ((stub_fw *)self->impl)->engaged;
}
static bool stub_requires_priv(pmx_firewall *self) {
    (void)self;
    return false;
}
static void stub_destroy(pmx_firewall *self) {
    if (self == NULL) {
        return;
    }
    free(self->impl);
    free(self);
}

pmx_firewall *pmx_firewall_stub_create(void) {
    pmx_firewall *fw = (pmx_firewall *)calloc(1, sizeof(*fw));
    stub_fw *impl = (stub_fw *)calloc(1, sizeof(*impl));
    if (fw == NULL || impl == NULL) {
        free(fw);
        free(impl);
        return NULL;
    }
    fw->name = "stub";
    fw->impl = impl;
    fw->engage = stub_engage;
    fw->disengage = stub_disengage;
    fw->is_engaged = stub_is_engaged;
    fw->requires_privilege = stub_requires_priv;
    fw->destroy = stub_destroy;
    return fw;
}

/* Platform selection lives here; platform files provide the concrete creators. */
#if defined(PMX_PLATFORM_WINDOWS)
extern pmx_firewall *pmx_firewall_wfp_create(void);
#elif defined(PMX_PLATFORM_MACOS)
extern pmx_firewall *pmx_firewall_pf_create(void);
#endif

pmx_firewall *pmx_firewall_platform_create(void) {
#if defined(PMX_PLATFORM_WINDOWS)
    pmx_firewall *fw = pmx_firewall_wfp_create();
    return fw ? fw : pmx_firewall_stub_create();
#elif defined(PMX_PLATFORM_MACOS)
    pmx_firewall *fw = pmx_firewall_pf_create();
    return fw ? fw : pmx_firewall_stub_create();
#else
    return pmx_firewall_stub_create();
#endif
}

/* ------------------------------------------------- lockdown controller --- */

struct pmx_lockdown {
    pmx_lockdown_policy policy;
    pmx_firewall *fw; /* borrowed */
    pmx_fw_endpoint allow[PMX_MAX_ALLOWLIST];
    size_t allow_count;
    pmx_lockdown_state state;
    int fails;
    int succ;
    bool armed;
};

pmx_lockdown *pmx_lockdown_create(const pmx_lockdown_policy *policy,
                                  pmx_firewall *fw) {
    pmx_lockdown *ld = (pmx_lockdown *)calloc(1, sizeof(*ld));
    if (ld == NULL) {
        return NULL;
    }
    if (policy != NULL) {
        ld->policy = *policy;
    } else {
        pmx_lockdown_policy_defaults(&ld->policy);
    }
    ld->fw = fw;
    ld->state = PMX_LD_INACTIVE;
    return ld;
}

void pmx_lockdown_destroy(pmx_lockdown *ld) {
    if (ld == NULL) {
        return;
    }
    if (ld->armed && ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
        ld->fw->disengage(ld->fw);
    }
    free(ld);
}

static bool mode_blocks(pmx_lockdown_mode m) {
    return m == PMX_LOCKDOWN_FAIL_CLOSED || m == PMX_LOCKDOWN_FAIL_BACKUP;
}

/* A mode we don't recognize (corrupt or hand-edited profile — pmx_profile.c
 * casts the JSON int straight to the enum) must never silently mean "never
 * block": every non-blocking path here would then report "Armed — healthy"
 * while enforcing nothing. For a kill switch the safe default is to block. */
static pmx_lockdown_mode sanitize_mode(pmx_lockdown_mode m) {
    switch (m) {
    case PMX_LOCKDOWN_OFF:
    case PMX_LOCKDOWN_FAIL_CLOSED:
    case PMX_LOCKDOWN_FAIL_BACKUP:
    case PMX_LOCKDOWN_FAIL_OPEN:
        return m;
    default:
        break;
    }
    PMX_LOGW("[lockdown] unrecognized mode %d in policy — treating it as fail "
             "closed rather than letting traffic through.",
             (int)m);
    return PMX_LOCKDOWN_FAIL_CLOSED;
}

/* Engage the firewall. Returns the firewall's status so callers can tell the
 * truth about whether enforcement actually happened — a NULL firewall is a
 * FAILURE to enforce, not a silent success. */
static pmx_status apply_engage(pmx_lockdown *ld) {
    if (ld->fw == NULL) {
        return PMX_ERR_FIREWALL;
    }
    return ld->fw->engage(ld->fw, ld->allow, ld->allow_count, &ld->policy);
}

/* Bring the firewall and the reported state into line with the current policy.
 * Called when arming and whenever the mode changes while armed.
 *
 * Without this, `set_policy` only copied the struct: switching Off/fail-open ->
 * fail-closed left `state` at INACTIVE/FAILED_OPEN, and the trip branch in
 * on_health only fires from ARMED_HEALTHY — so the kill switch could never
 * engage, silently, for the rest of the session. The reverse (-> Off) left the
 * firewall engaged forever with a stale state. */
static pmx_status lockdown_reconcile(pmx_lockdown *ld) {
    ld->fails = 0;
    ld->succ = 0;

    if (ld->policy.mode == PMX_LOCKDOWN_OFF) {
        if (ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
            ld->fw->disengage(ld->fw);
        }
        ld->state = PMX_LD_INACTIVE;
        return PMX_OK;
    }

    if (mode_blocks(ld->policy.mode)) {
        pmx_status st = PMX_OK;
        if (ld->fw == NULL || !ld->fw->is_engaged(ld->fw)) {
            st = apply_engage(ld); /* kill-switch: only the allowlist is reachable */
        }
        if (st != PMX_OK) {
            /* We meant to block and could not (no firewall object, or WFP
             * refused because we aren't elevated). Traffic is NOT blocked —
             * report that instead of a reassuring "blocking". */
            PMX_LOGE("[lockdown] could not engage the firewall (%s) — traffic is "
                     "NOT being blocked.",
                     pmx_status_str(st));
            ld->state = PMX_LD_FAILED_OPEN;
            return st;
        }
        ld->state = ld->policy.block_until_verified ? PMX_LD_TRIPPED_BLOCKING
                                                     : PMX_LD_ARMED_HEALTHY;
        return PMX_OK;
    }

    /* FAIL_OPEN never blocks — make sure nothing is left engaged behind us. */
    if (ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
        ld->fw->disengage(ld->fw);
    }
    ld->state = PMX_LD_ARMED_HEALTHY;
    return PMX_OK;
}

void pmx_lockdown_set_policy(pmx_lockdown *ld, const pmx_lockdown_policy *policy) {
    if (ld == NULL || policy == NULL) {
        return;
    }
    pmx_lockdown_mode prev = ld->policy.mode;
    ld->policy = *policy;
    ld->policy.mode = sanitize_mode(ld->policy.mode);

    /* Only reconcile on an actual mode change: the settings panel calls this
     * every frame, and re-engaging (and resetting the hysteresis counters) each
     * frame would destroy the trip/restore behaviour entirely. */
    if (ld->armed && ld->policy.mode != prev) {
        lockdown_reconcile(ld);
        PMX_LOGI("[lockdown] mode changed to %s -> %s",
                 pmx_lockdown_mode_str(ld->policy.mode),
                 pmx_lockdown_state_str(ld->state));
    }
}

void pmx_lockdown_set_allowlist(pmx_lockdown *ld, const pmx_fw_endpoint *eps,
                                size_t count) {
    if (ld == NULL) {
        return;
    }
    ld->allow_count = 0;
    for (size_t i = 0; i < count && ld->allow_count < PMX_ARRAY_LEN(ld->allow);
         i++) {
        ld->allow[ld->allow_count++] = eps[i];
    }
    /* Re-apply live if we're currently enforcing. */
    if (ld->armed && ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
        apply_engage(ld);
    }
}

pmx_status pmx_lockdown_arm(pmx_lockdown *ld) {
    if (ld == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    ld->armed = true;
    ld->policy.mode = sanitize_mode(ld->policy.mode);
    pmx_status st = lockdown_reconcile(ld);
    PMX_LOGI("[lockdown] armed: %s -> %s", pmx_lockdown_mode_str(ld->policy.mode),
             pmx_lockdown_state_str(ld->state));
    return st;
}

pmx_status pmx_lockdown_disarm(pmx_lockdown *ld) {
    if (ld == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    ld->armed = false;
    if (ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
        ld->fw->disengage(ld->fw);
    }
    ld->state = PMX_LD_INACTIVE;
    PMX_LOGI("[lockdown] disarmed");
    return PMX_OK;
}

pmx_status pmx_lockdown_on_health(pmx_lockdown *ld, bool healthy, bool *changed) {
    if (changed != NULL) {
        *changed = false;
    }
    if (ld == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (!ld->armed || ld->policy.mode == PMX_LOCKDOWN_OFF) {
        return PMX_OK;
    }

    if (healthy) {
        ld->succ++;
        ld->fails = 0;
    } else {
        ld->fails++;
        ld->succ = 0;
    }

    pmx_lockdown_state prev = ld->state;

    if (healthy && ld->state != PMX_LD_ARMED_HEALTHY &&
        ld->succ >= ld->policy.successes_before_restore) {
        /* Proxy recovered. */
        if (ld->policy.mode == PMX_LOCKDOWN_FAIL_OPEN && ld->fw != NULL &&
            ld->fw->is_engaged(ld->fw)) {
            ld->fw->disengage(ld->fw);
        }
        ld->state = PMX_LD_ARMED_HEALTHY;
    } else if (!healthy && ld->state == PMX_LD_ARMED_HEALTHY &&
               ld->fails >= ld->policy.failures_before_trip) {
        /* Proxy went down — act per policy. A failed engage must not be
         * reported as a blocking state: nothing is actually blocked. */
        switch (ld->policy.mode) {
        case PMX_LOCKDOWN_FAIL_CLOSED: {
            pmx_status est = PMX_OK;
            if (ld->fw == NULL || !ld->fw->is_engaged(ld->fw)) {
                est = apply_engage(ld);
            }
            if (est != PMX_OK) {
                PMX_LOGE("[lockdown] tripped but could not engage the firewall "
                         "(%s) — traffic is NOT being blocked.",
                         pmx_status_str(est));
                ld->state = PMX_LD_FAILED_OPEN;
            } else {
                ld->state = PMX_LD_TRIPPED_BLOCKING;
            }
            break;
        }
        case PMX_LOCKDOWN_FAIL_BACKUP: {
            pmx_status est = PMX_OK;
            if (ld->fw == NULL || !ld->fw->is_engaged(ld->fw)) {
                est = apply_engage(ld);
            }
            if (est != PMX_OK) {
                PMX_LOGE("[lockdown] failover could not engage the firewall "
                         "(%s) — traffic is NOT being blocked.",
                         pmx_status_str(est));
                ld->state = PMX_LD_FAILED_OPEN;
            } else {
                ld->state = PMX_LD_FAILING_OVER;
            }
            break;
        }
        case PMX_LOCKDOWN_FAIL_OPEN:
            if (ld->fw != NULL && ld->fw->is_engaged(ld->fw)) {
                ld->fw->disengage(ld->fw);
            }
            ld->state = PMX_LD_FAILED_OPEN;
            break;
        default:
            break;
        }
    }

    if (ld->state != prev) {
        if (changed != NULL) {
            *changed = true;
        }
        PMX_LOGW("[lockdown] %s -> %s (%s)", pmx_lockdown_state_str(prev),
                 pmx_lockdown_state_str(ld->state),
                 healthy ? "healthy" : "unhealthy");
    }
    return PMX_OK;
}

pmx_lockdown_state pmx_lockdown_get_state(const pmx_lockdown *ld) {
    return ld ? ld->state : PMX_LD_INACTIVE;
}
int pmx_lockdown_consecutive_failures(const pmx_lockdown *ld) {
    return ld ? ld->fails : 0;
}
int pmx_lockdown_consecutive_successes(const pmx_lockdown *ld) {
    return ld ? ld->succ : 0;
}
