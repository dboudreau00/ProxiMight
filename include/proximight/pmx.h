/*
 * pmx.h — umbrella header + version. Include this to pull in the whole engine.
 */
#ifndef PROXIMIGHT_PMX_H
#define PROXIMIGHT_PMX_H

#define PMX_VERSION_MAJOR 0
#define PMX_VERSION_MINOR 2
#define PMX_VERSION_PATCH 0
/* -alpha is load-bearing, not decoration: per-app traffic REDIRECTION has never
 * been observed on the wire (caps.real == false). Drop the suffix when the
 * WinDivert wire test in docs/SETUP-WINDIVERT.md passes. */
#define PMX_VERSION_STRING "0.2.0-alpha"
#define PMX_APP_NAME "ProxiMight"

#include "proximight/pmx_types.h"
#include "proximight/pmx_error.h"
#include "proximight/pmx_log.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_proxy.h"
#include "proximight/pmx_socks.h"        /* SOCKS4/4a/5 codecs   */
#include "proximight/pmx_http_connect.h" /* HTTP CONNECT + base64 */
#include "proximight/pmx_rule.h"
#include "proximight/pmx_chain.h"
#include "proximight/pmx_profile.h"
#include "proximight/pmx_protect.h"
#include "proximight/pmx_checker.h"
#include "proximight/pmx_procinfo.h"
#include "proximight/pmx_netpath.h"
#include "proximight/pmx_vpn.h"
#include "proximight/pmx_proc.h"
#include "proximight/pmx_relay.h"
#include "proximight/pmx_nat.h"
#include "proximight/pmx_backend.h"
#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_engine.h"

#endif /* PROXIMIGHT_PMX_H */
