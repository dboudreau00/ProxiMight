/*
 * firewall_wfp.c — Windows kill-switch firewall backend (SCAFFOLD).
 *
 * Planned design for the lockdown allowlist ("only the proxy is reachable"):
 *
 *   Option A (no admin at install, per-run): Windows Filtering Platform (WFP)
 *     via fwpuclnt.dll. Add sublayer + FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
 *     filters: a low-weight BLOCK for all outbound, plus higher-weight PERMIT
 *     filters for the proxy endpoint(s) and loopback. Optionally block :53 to
 *     force DNS through the tunnel and block all V6 to kill IPv6 leaks. WFP
 *     dynamic filters auto-clean when the engine handle closes — good for a
 *     kill switch (crash => rules gone).
 *
 *   Option B (simpler, coarser): shell out to `netsh advfirewall` / the
 *     INetFwPolicy2 COM API to flip the profile to block-outbound-by-default and
 *     add allow rules. Coarser and slower to toggle.
 *
 * Both require Administrator. requires_privilege() therefore returns true in the
 * real build. Until implemented (gate: PMX_HAVE_WFP), the factory returns NULL
 * and lockdown uses the stub firewall (state-tracking + logging only).
 */
#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_log.h"

#include <stddef.h>

#ifdef PMX_HAVE_WFP

/* Real WFP-backed pmx_firewall implementation lands here. */
pmx_firewall *pmx_firewall_wfp_create(void) {
    PMX_LOGW("[firewall:wfp] PMX_HAVE_WFP set but implementation is a scaffold; "
             "falling back to stub firewall.");
    return NULL;
}

#else /* !PMX_HAVE_WFP */

pmx_firewall *pmx_firewall_wfp_create(void) {
    PMX_LOGI("[firewall:wfp] not built. Real fail-closed enforcement needs WFP "
             "(fwpuclnt) + Administrator; define PMX_HAVE_WFP to enable. Using "
             "the stub firewall (logs intended blocks) for now.");
    return NULL;
}

#endif
