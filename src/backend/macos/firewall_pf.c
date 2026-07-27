/*
 * firewall_pf.c — macOS kill-switch firewall backend (SCAFFOLD).
 *
 * Planned design for the lockdown allowlist using pf (packet filter):
 *
 *   - Load a dedicated ProxiMight pf anchor (so we never stomp the user's own
 *     rules), e.g. write to /etc/pf.anchors/proximight and reference it from the
 *     main ruleset, or push rules directly via pfctl / DIOCADDRULE ioctls.
 *   - Default posture: `block drop out all`, then `pass out proto tcp to
 *     <proxy_ip> port <proxy_port>` for each allowlisted endpoint plus loopback.
 *   - DNS-leak guard: `block drop out proto { udp tcp } to any port 53` unless
 *     it targets the proxy. IPv6 leak guard: `block drop out inet6 all`.
 *   - On disengage (or crash-safety via a watchdog), flush the anchor to restore
 *     connectivity.
 *
 * Requires root (pfctl / the pf device). requires_privilege() returns true in
 * the real build. Gated behind PMX_HAVE_PF_FIREWALL; until then the factory
 * returns NULL and lockdown uses the stub firewall.
 */
#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_log.h"

#include <stddef.h>

#ifdef PMX_HAVE_PF_FIREWALL

pmx_firewall *pmx_firewall_pf_create(void) {
    PMX_LOGW("[firewall:pf] PMX_HAVE_PF_FIREWALL set but implementation is a "
             "scaffold; falling back to stub firewall.");
    return NULL;
}

#else

pmx_firewall *pmx_firewall_pf_create(void) {
    PMX_LOGI("[firewall:pf] not built. Real fail-closed enforcement needs pf + "
             "root; define PMX_HAVE_PF_FIREWALL to enable. Using the stub "
             "firewall for now.");
    return NULL;
}

#endif
