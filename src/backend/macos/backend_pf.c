/*
 * backend_pf.c — macOS per-application redirection (SCAFFOLD).
 *
 * macOS is the harder platform. Two tiers:
 *
 *   Tier 1 — the "real" per-app path (GATED by Apple):
 *     NetworkExtension with a NEAppProxyProvider (per-app) or
 *     NETransparentProxyProvider (system-wide), packaged as a System Extension
 *     inside the .app. Requires:
 *       - the com.apple.developer.networking.networkextension entitlement,
 *       - Apple *special approval* to ship a NetworkExtension system extension,
 *       - a paid Apple Developer account + notarization,
 *       - user approval in System Settings.
 *     The provider is Swift/Obj-C, bridged to this C core over a thin shim.
 *
 *   Tier 2 — the pragmatic dev path (no Apple gate, limited per-app fidelity):
 *     Configure the pf firewall to redirect outbound TCP (rdr/route-to) into a
 *     local transparent SOCKSifier bound to a `utun` device (tun2socks-style).
 *     pf matches by user/group and port far more easily than by process, so
 *     true per-app rules are limited here — good enough for development and
 *     testing, not the finished product.
 *
 * Gated behind PMX_HAVE_PF_BACKEND. Until then the factory returns NULL and the
 * engine uses the stub backend.
 */
#include "proximight/pmx_backend.h"
#include "proximight/pmx_log.h"

#include <stddef.h>

#ifdef PMX_HAVE_PF_BACKEND

pmx_backend *pmx_backend_pf_create(void) {
    PMX_LOGW("[backend:pf] PMX_HAVE_PF_BACKEND set but implementation is a "
             "scaffold; falling back to stub.");
    return NULL;
}

#else

pmx_backend *pmx_backend_pf_create(void) {
    PMX_LOGI("[backend:pf] not built. macOS redirection needs either a "
             "NetworkExtension system extension (Apple-approved entitlement) or "
             "a pf+utun tun2socks relay. Using the stub backend for now.");
    return NULL;
}

#endif
