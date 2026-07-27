/*
 * backend_windivert.c — Windows per-application traffic backend.
 *
 * STATUS: real per-app observation AND real blocking. Proxy redirection is the
 * one remaining piece (see "What's still missing" below).
 *
 * How it works
 * ------------
 * We open a WinDivert handle at WINDIVERT_LAYER_SOCKET filtering outbound
 * TCP/UDP. Every SOCKET_CONNECT event carries the owning ProcessId plus both
 * endpoints, so a fully attributed pmx_flow can be built without any TCP-table
 * correlation (pmx_procinfo resolves the PID to an image name/path).
 *
 * The handle is NOT opened in sniff mode, which means we decide the fate of
 * each connect inline:
 *   - allow  -> WinDivertSend() the address back, and the connect proceeds
 *   - block  -> simply don't send it, and the connect fails
 *
 * Because that decision has to happen on this thread, right now, we use the
 * engine's `decide` callback, which answers from a lock-protected snapshot of
 * the profile (see pmx_engine_decide). The flow is *also* reported through the
 * flow callback so the Connections view logs it; the engine re-resolves it
 * there for display, which is redundant but keeps the UI path unchanged.
 *
 * Verdict handling:
 *   DIRECT -> allow
 *   BLOCK  -> drop (the application sees the connection fail)
 *   PROXY  -> we cannot redirect yet. Rather than silently leak the connection
 *             out unproxied, the default is to fail closed and block it
 *             (cfg.block_when_cannot_proxy, which the engine derives from the
 *             lockdown mode). Set lockdown to "fail open" to allow direct
 *             instead — leaky, but explicit.
 *
 * What's still missing (Phase 1c)
 * -------------------------------
 * Actual proxying needs a second handle at WINDIVERT_LAYER_NETWORK that NATs
 * matched connections into the local relay:
 *   1. pmx_relay is already implemented and tested (tests/test_relay.c): give
 *      it the source port, real destination and chosen proxy via
 *      pmx_relay_register(), and it performs the proxy handshake and splices.
 *   2. The missing glue is the packet rewrite: on the outbound SYN, replace the
 *      destination with 127.0.0.1:<relay port>, remember the mapping keyed by
 *      source port, recompute checksums with WinDivertHelperCalcChecksums(),
 *      and rewrite the reverse path so replies appear to come from the original
 *      destination.
 * That rewrite is the part that cannot be verified without the driver and a
 * live machine, so it is deliberately not written blind.
 *
 * Requires Administrator. Gated behind PMX_HAVE_WINDIVERT, which CMake defines
 * when it finds the SDK (see docs/SETUP-WINDIVERT.md). Without it the factory
 * returns NULL and the engine falls back to the stub backend.
 *
 * NOTE: a non-sniff handle gates real connections system-wide. If this process
 * stops servicing the queue, matching connects stall until the handle closes.
 * Keep the pump loop free of blocking work.
 */
#include "proximight/pmx_backend.h"
#include "proximight/pmx_log.h"

#include <stddef.h>

#ifdef PMX_HAVE_WINDIVERT

#include "proximight/pmx_procinfo.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_relay.h"
#include "proximight/pmx_nat.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "windivert.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PMX_LOOPBACK_HOST_ORDER 0x7F000001u /* 127.0.0.1 */

typedef struct wd_impl {
    HANDLE handle;      /* SOCKET layer: verdicts                       */
    HANDLE net_handle;  /* NETWORK layer: the actual packet rewrite     */
    pmx_thread *net_pump;
    pmx_relay *relay;   /* local SOCKSifier that carries proxied flows  */
    pmx_port relay_port;
    pmx_nat *nat;       /* src_port -> original destination             */
    DWORD own_pid;      /* so we never proxify ourselves (see wd_pump)  */
    uint64_t n_redirected;
    pmx_flow_cb cb;
    void *cb_user;
    pmx_decide_fn decide;
    void *decide_user;
    pmx_mutex *mutex;
    pmx_thread *pump;
    bool running;
    bool block_when_cannot_proxy;
    uint64_t counter;
    uint64_t n_allowed, n_blocked;
} wd_impl;

static bool wd_running(wd_impl *im) {
    pmx_mutex_lock(im->mutex);
    bool r = im->running;
    pmx_mutex_unlock(im->mutex);
    return r;
}

/* Let the intercepted operation proceed. */
static void wd_allow(HANDLE h, const WINDIVERT_ADDRESS *addr) {
    UINT sent = 0;
    WinDivertSend(h, NULL, 0, &sent, addr);
}

static void wd_pump(void *arg) {
    pmx_backend *self = (pmx_backend *)arg;
    wd_impl *im = (wd_impl *)self->impl;

    while (wd_running(im)) {
        WINDIVERT_ADDRESS addr;
        UINT recv_len = 0;
        memset(&addr, 0, sizeof(addr));

        if (!WinDivertRecv(im->handle, NULL, 0, &recv_len, &addr)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_DATA) {
                break; /* handle shut down */
            }
            if (!wd_running(im)) {
                break;
            }
            pmx_sleep_ms(5);
            continue;
        }

        /* Anything that isn't an outbound connect just passes through. */
        UINT8 proto = addr.Socket.Protocol;
        if (addr.Event != WINDIVERT_EVENT_SOCKET_CONNECT ||
            (proto != IPPROTO_TCP && proto != IPPROTO_UDP)) {
            wd_allow(im->handle, &addr);
            continue;
        }

        /* Our OWN connections are never subject to the user's rules.
         *
         * The relay dials the proxy from inside this very process, so an ordinary
         * Proxifier-style rule ("any application -> proxy") matches it: it would
         * be registered with the relay and the NAT table, and the network layer
         * would then rewrite it straight back into the relay — ProxiMight
         * proxying itself, forever. The capture filter already guarantees we
         * cannot recapture packets we INJECT; this is the other half, the ones we
         * ORIGINATE. It also keeps a Block rule from strangling our own checker
         * and egress probes. */
        if ((DWORD)addr.Socket.ProcessId == im->own_pid) {
            wd_allow(im->handle, &addr);
            continue;
        }

        pmx_flow f;
        memset(&f, 0, sizeof(f));

        pmx_mutex_lock(im->mutex);
        f.flow_id = ++im->counter;
        pmx_flow_cb cb = im->cb;
        void *cb_user = im->cb_user;
        pmx_decide_fn decide = im->decide;
        void *decide_user = im->decide_user;
        bool fail_closed = im->block_when_cannot_proxy;
        pmx_mutex_unlock(im->mutex);

        f.pid = (uint32_t)addr.Socket.ProcessId;
        pmx_proc_info pi;
        if (pmx_procinfo_for_pid(f.pid, &pi) == PMX_OK && pi.name[0] != '\0') {
            pmx_strlcpy(f.app_name, pi.name, sizeof(f.app_name));
            pmx_strlcpy(f.app_path, pi.path, sizeof(f.app_path));
        } else {
            snprintf(f.app_name, sizeof(f.app_name), "pid %u", (unsigned)f.pid);
        }

        char host[128];
        host[0] = '\0';
        if (addr.IPv6) {
            WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, host,
                                             (UINT)sizeof(host));
        } else {
            WinDivertHelperFormatIPv4Address(addr.Socket.RemoteAddr[0], host,
                                             (UINT)sizeof(host));
        }
        pmx_strlcpy(f.dst_host, host, sizeof(f.dst_host));
        f.dst_port = (pmx_port)addr.Socket.RemotePort;
        f.udp = (proto == IPPROTO_UDP);
        f.created_ms = pmx_now_ms();

        /* Report for the connections log. */
        if (cb != NULL) {
            cb(cb_user, &f);
        }

        /* Decide inline. Without a decider we must not silently gate traffic. */
        pmx_decision d;
        memset(&d, 0, sizeof(d));
        d.verdict = PMX_VERDICT_DIRECT;
        if (decide != NULL) {
            decide(decide_user, &f, &d);
        }

        bool allow = true;
        switch (d.verdict) {
        case PMX_VERDICT_DIRECT:
            allow = true;
            break;
        case PMX_VERDICT_BLOCK:
            allow = false;
            PMX_LOGI("[backend:windivert] BLOCKED %s -> %s:%u [%s]", f.app_name,
                     f.dst_host, (unsigned)f.dst_port, d.rule_name);
            break;
        case PMX_VERDICT_PROXY: {
            pmx_port sport = (pmx_port)addr.Socket.LocalPort;
            bool v4 = !addr.IPv6;
            /* UDP must be excluded here even though the SOCKET layer reports it.
             * The relay and the NAT table are TCP constructs and the NETWORK
             * filter begins with "tcp and", so a UDP flow could be registered and
             * ALLOWED while no datagram was ever diverted — the app's DNS or QUIC
             * traffic leaving in the clear with the log claiming "redirecting".
             * Treat it like any other flow we cannot honour: fail closed by
             * default. (IPv6 is refused the same way, via v4.) */
            bool routable = (d.via_count > 0 && im->relay != NULL &&
                             im->nat != NULL && v4 && !f.udp && sport != 0);
            bool registered = false;
            if (routable) {
                /* Register with BOTH the relay and the NAT table before letting
                 * the SYN out. If either registration fails (e.g. the tables are
                 * full), we must NOT allow the connection: without a NAT entry
                 * the network pump won't rewrite it, so it would egress DIRECT
                 * to the real destination — a silent proxy bypass. A failed
                 * registration is treated exactly like "cannot be redirected". */
                pmx_status rreg = pmx_relay_register(im->relay, sport, f.dst_host,
                                                     f.dst_port, d.via_chain,
                                                     d.via_count);
                pmx_status nreg = PMX_ERR_STATE;
                if (rreg == PMX_OK) {
                    nreg = pmx_nat_add(im->nat, addr.Socket.LocalAddr[0], sport,
                                       addr.Socket.RemoteAddr[0], f.dst_port,
                                       pmx_now_ms());
                }
                registered = (rreg == PMX_OK && nreg == PMX_OK);
            }
            if (registered) {
                allow = true;
                PMX_LOGD("[backend:windivert] redirecting %s -> %s:%u via '%s'"
                         " (%zu hop(s))",
                         f.app_name, f.dst_host, (unsigned)f.dst_port,
                         d.via_chain[0].label, d.via_count);
            } else {
                /* Under-proxying is worse than not proxying at all: a chain we
                 * can only partially honour must never quietly go out with less
                 * protection than the user asked for. */
                const char *why =
                    (!v4)          ? "IPv6 is not handled yet"
                    : (f.udp)      ? "UDP is not redirected yet (needs SOCKS5 "
                                     "UDP associate)"
                    : (sport == 0) ? "the flow has no local source port"
                    : (d.via_count == 0)
                        ? ((d.via_hop_count > 0)
                               ? "a hop in the chain is missing or disabled"
                               : "no usable proxy resolved")
                        : "relay/NAT registration failed (tables full?)";
                allow = !fail_closed;
                PMX_LOGW("[backend:windivert] %s -> %s:%u wanted '%s' [%s] but "
                         "cannot be redirected (%s) — %s",
                         f.app_name, f.dst_host, (unsigned)f.dst_port,
                         d.via_label, d.rule_name, why,
                         allow ? "ALLOWING DIRECT (leaky; lockdown is fail-open)"
                               : "BLOCKING (fail closed)");
            }
            break;
        }
        default:
            allow = true;
            break;
        }

        if (allow) {
            wd_allow(im->handle, &addr);
            pmx_mutex_lock(im->mutex);
            im->n_allowed++;
            pmx_mutex_unlock(im->mutex);
        } else {
            /* Not sending the address back is what blocks the connect. */
            pmx_mutex_lock(im->mutex);
            im->n_blocked++;
            pmx_mutex_unlock(im->mutex);
        }
    }
}

/* ---- NETWORK layer: the actual redirection -------------------------------
 *
 * A flow the engine chose to proxy is rewritten so BOTH endpoints are loopback:
 *
 *   app:52344 -> 93.184.216.34:443   becomes   127.0.0.1:52344 -> 127.0.0.1:relay
 *
 * and the reply is rewritten back, so the application still believes it spoke
 * to 93.184.216.34:443. pmx_nat remembers the original destination; the relay
 * (already registered by the socket layer) performs the proxy handshake.
 *
 * The capture filter is deliberately narrow so we can never recapture our own
 * injected packets — that would loop forever:
 *   - the outbound clause excludes packets already headed to loopback (ours)
 *   - the inbound clause only matches replies coming FROM the relay port
 */
static void wd_net_pump(void *arg) {
    pmx_backend *self = (pmx_backend *)arg;
    wd_impl *im = (wd_impl *)self->impl;
    static unsigned char packet[0xFFFF];

    while (wd_running(im)) {
        UINT len = 0;
        WINDIVERT_ADDRESS addr;
        memset(&addr, 0, sizeof(addr));

        if (!WinDivertRecv(im->net_handle, packet, sizeof(packet), &len, &addr)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_DATA) {
                break;
            }
            if (!wd_running(im)) {
                break;
            }
            pmx_sleep_ms(5);
            continue;
        }

        PWINDIVERT_IPHDR ip = NULL;
        PWINDIVERT_TCPHDR tcp = NULL;
        WinDivertHelperParsePacket(packet, len, &ip, NULL, NULL, NULL, NULL, &tcp,
                                   NULL, NULL, NULL, NULL, NULL);

        bool rewrote = false;
        if (ip != NULL && tcp != NULL) {
            uint64_t now = pmx_now_ms();
            pmx_nat_entry e;
            if (addr.Outbound) {
                pmx_port sport = (pmx_port)ntohs(tcp->SrcPort);
                if (pmx_nat_find(im->nat, sport, now, &e)) {
                    /* A source-port match alone is NOT proof this is the flow we
                     * registered. The OS recycles ephemeral ports, so a brand new
                     * connection to somewhere else can inherit a port whose entry
                     * is still live — and rewriting that one would drag an
                     * unrelated flow into the relay and hand it to the previous
                     * flow's destination. Confirm the packet is actually headed
                     * where we recorded before touching it. */
                    uint32_t dst = ntohl(ip->DstAddr);
                    pmx_port dport = (pmx_port)ntohs(tcp->DstPort);
                    if (dst == e.orig_dst_addr && dport == e.orig_dst_port) {
                        /* Make it a loopback conversation with the relay. */
                        ip->SrcAddr = htonl(PMX_LOOPBACK_HOST_ORDER);
                        ip->DstAddr = htonl(PMX_LOOPBACK_HOST_ORDER);
                        tcp->DstPort = htons(im->relay_port);
                        addr.Loopback = 1;
                        rewrote = true;
                    } else {
                        /* Left alone deliberately. Seeing this constantly for
                         * flows you DID expect to be proxied is the signature of
                         * a byte-order mismatch between the SOCKET layer (which
                         * fills the NAT entry) and the packet headers — worth
                         * checking first if "redirecting" is logged but
                         * n_redirected stays at 0. */
                        PMX_LOGD("[backend:windivert] sport %u matches a mapping "
                                 "for a different destination; not rewriting",
                                 (unsigned)sport);
                    }
                }
            } else {
                /* Reply from the relay: restore the endpoints the app expects. */
                pmx_port dport = (pmx_port)ntohs(tcp->DstPort);
                if (pmx_nat_find(im->nat, dport, now, &e)) {
                    ip->SrcAddr = htonl(e.orig_dst_addr);
                    ip->DstAddr = htonl(e.src_addr);
                    tcp->SrcPort = htons(e.orig_dst_port);
                    addr.Loopback = 0;
                    rewrote = true;
                }
            }
        }

        if (rewrote) {
            /* Addresses and ports moved, so both checksums must be redone. */
            WinDivertHelperCalcChecksums(packet, len, &addr, 0);
            pmx_mutex_lock(im->mutex);
            im->n_redirected++;
            pmx_mutex_unlock(im->mutex);
        }

        UINT sent = 0;
        WinDivertSend(im->net_handle, packet, len, &sent, &addr);
    }
}

/* Relay close callback: a proxied flow's relay side ended.
 *
 * MARK it closed rather than deleting it. The application's socket for this
 * source port can still be open — it is only now learning the connection went
 * away — and wd_net_pump rewrites a packet ONLY when pmx_nat_find hits. Deleting
 * the mapping here would send the app's next packet straight to the real
 * destination from the real source IP: precisely the silent proxy bypass the
 * rest of the NAT work exists to prevent. A closed entry keeps matching (traffic
 * still goes to the relay, which refuses it) while becoming reclaimable, so the
 * table still cannot wedge. Runs on a relay worker thread; pmx_nat is locked. */
static void wd_on_flow_end(void *user, pmx_port src_port) {
    wd_impl *im = (wd_impl *)user;
    if (im != NULL && im->nat != NULL) {
        pmx_nat_mark_closed(im->nat, src_port);
    }
}

static pmx_status wd_start(pmx_backend *self, const pmx_backend_config *cfg) {
    wd_impl *im = (wd_impl *)self->impl;
    if (wd_running(im)) {
        return PMX_OK;
    }

    pmx_mutex_lock(im->mutex);
    im->block_when_cannot_proxy = (cfg == NULL) ? true
                                                : cfg->block_when_cannot_proxy;
    pmx_decide_fn have_decide = im->decide;
    pmx_mutex_unlock(im->mutex);

    if (have_decide == NULL) {
        /* Refuse to gate real traffic with no way to decide its fate. */
        PMX_LOGE("[backend:windivert] no decision callback bound; refusing to "
                 "intercept traffic.");
        return PMX_ERR_STATE;
    }

    /* No SNIFF flag: we must be able to drop a connect to enforce BLOCK. */
    HANDLE h = WinDivertOpen("outbound and (tcp or udp)", WINDIVERT_LAYER_SOCKET,
                             0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        /* Name the actual cause. The old message blamed missing files for every
         * failure, which sends you hunting through a directory that is fine
         * when the real problem is the filter, the driver version, or Secure
         * Boot. Each of these has a different fix. */
        switch (e) {
        case ERROR_ACCESS_DENIED:
            PMX_LOGE("[backend:windivert] access denied — ProxiMight must run as "
                     "Administrator to load the WinDivert driver.");
            return PMX_ERR_PERMISSION;
        case ERROR_INVALID_PARAMETER:
            PMX_LOGE("[backend:windivert] the driver REJECTED the open (error 87, "
                     "invalid parameter). The files are present — this is a "
                     "filter/layer/version problem, not a missing DLL. Most "
                     "likely WinDivert.dll and WinDivert64.sys are different "
                     "versions, or the loaded 'WinDivert' driver service is an "
                     "older build than the .sys beside the exe. Check with: "
                     "sc.exe query WinDivert");
            return PMX_ERR_BACKEND;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_MOD_NOT_FOUND:
            PMX_LOGE("[backend:windivert] WinDivert.dll / WinDivert64.sys were not "
                     "found next to the executable (error %lu).",
                     (unsigned long)e);
            return PMX_ERR_BACKEND;
        case ERROR_INVALID_IMAGE_HASH:
            PMX_LOGE("[backend:windivert] Windows refused the driver's signature "
                     "(error 577). Secure Boot or a driver-signing policy is "
                     "blocking it; do NOT work around this with an unsigned "
                     "driver.");
            return PMX_ERR_BACKEND;
        case ERROR_SERVICE_DOES_NOT_EXIST:
            PMX_LOGE("[backend:windivert] the WinDivert driver service could not "
                     "be installed (error %lu).",
                     (unsigned long)e);
            return PMX_ERR_BACKEND;
        default:
            PMX_LOGE("[backend:windivert] WinDivertOpen failed (error %lu).",
                     (unsigned long)e);
            return PMX_ERR_BACKEND;
        }
    }

    /* The relay carries proxied flows; the NAT table remembers where they were
     * really going. Both must exist before the network pump starts. */
    pmx_status rst = pmx_relay_start(&im->relay, 0);
    if (rst != PMX_OK) {
        WinDivertClose(h);
        PMX_LOGE("[backend:windivert] could not start the local relay");
        return rst;
    }
    im->relay_port = pmx_relay_port(im->relay);
    im->nat = pmx_nat_create(1024, 120000);
    if (im->nat == NULL) {
        pmx_relay_stop(im->relay);
        im->relay = NULL;
        WinDivertClose(h);
        return PMX_ERR_NO_MEMORY;
    }
    /* When a relayed flow ends, drop its NAT entry so the table doesn't wedge
     * with dead connections — that is what lets pmx_nat_add fail closed on a
     * full table instead of evicting (and silently un-proxying) a live flow.
     * Safe against teardown: wd_stop() calls pmx_relay_stop() (which joins every
     * worker, so no callback is in flight) BEFORE pmx_nat_destroy(). */
    pmx_relay_set_close_cb(im->relay, wd_on_flow_end, im);

    /* Narrow enough that our own injected packets can never be recaptured:
     * outbound traffic not already bound for loopback, and replies from the
     * relay port only. */
    char net_filter[256];
    snprintf(net_filter, sizeof(net_filter),
             "tcp and ((outbound and ip.DstAddr != 127.0.0.1) or "
             "(inbound and ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == %u))",
             (unsigned)im->relay_port);

    HANDLE nh = WinDivertOpen(net_filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (nh == INVALID_HANDLE_VALUE) {
        PMX_LOGE("[backend:windivert] network-layer open failed (error %lu); "
                 "proxy redirection unavailable.",
                 (unsigned long)GetLastError());
        pmx_nat_destroy(im->nat);
        im->nat = NULL;
        pmx_relay_stop(im->relay);
        im->relay = NULL;
        WinDivertClose(h);
        return PMX_ERR_BACKEND;
    }

    pmx_mutex_lock(im->mutex);
    im->handle = h;
    im->net_handle = nh;
    im->running = true;
    pmx_mutex_unlock(im->mutex);

    if (pmx_thread_start(wd_pump, self, &im->pump) != PMX_OK ||
        pmx_thread_start(wd_net_pump, self, &im->net_pump) != PMX_OK) {
        pmx_mutex_lock(im->mutex);
        im->running = false;
        pmx_mutex_unlock(im->mutex);
        WinDivertClose(h);
        WinDivertClose(nh);
        im->handle = NULL;
        im->net_handle = NULL;
        return PMX_ERR_BACKEND;
    }

    PMX_LOGW("[backend:windivert] ENFORCING: real connections are now gated by "
             "your rules (Direct / Block / Proxy). Relay on 127.0.0.1:%u.",
             (unsigned)im->relay_port);
    return PMX_OK;
}

static pmx_status wd_stop(pmx_backend *self) {
    wd_impl *im = (wd_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    bool was = im->running;
    im->running = false;
    HANDLE h = im->handle;
    HANDLE nh = im->net_handle;
    pmx_thread *t = im->pump;
    pmx_thread *nt = im->net_pump;
    im->pump = NULL;
    im->net_pump = NULL;
    uint64_t allowed = im->n_allowed, blocked = im->n_blocked,
             redirected = im->n_redirected;
    pmx_mutex_unlock(im->mutex);

    /* Shutdown releases anything queued so traffic is never left gated. */
    if (h != NULL) {
        WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
    }
    if (nh != NULL) {
        WinDivertShutdown(nh, WINDIVERT_SHUTDOWN_BOTH);
    }
    if (t != NULL) {
        pmx_thread_join(t);
    }
    if (nt != NULL) {
        pmx_thread_join(nt);
    }
    if (h != NULL) {
        WinDivertClose(h);
    }
    if (nh != NULL) {
        WinDivertClose(nh);
    }

    pmx_mutex_lock(im->mutex);
    im->handle = NULL;
    im->net_handle = NULL;
    pmx_mutex_unlock(im->mutex);

    if (im->relay != NULL) {
        pmx_relay_stop(im->relay);
        im->relay = NULL;
    }
    if (im->nat != NULL) {
        pmx_nat_destroy(im->nat);
        im->nat = NULL;
    }

    if (was) {
        PMX_LOGI("[backend:windivert] stopped (%llu allowed, %llu blocked, "
                 "%llu packets redirected)",
                 (unsigned long long)allowed, (unsigned long long)blocked,
                 (unsigned long long)redirected);
    }
    return PMX_OK;
}

static bool wd_is_active(pmx_backend *self) {
    return wd_running((wd_impl *)self->impl);
}

static void wd_set_flow_cb(pmx_backend *self, pmx_flow_cb cb, void *user) {
    wd_impl *im = (wd_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    im->cb = cb;
    im->cb_user = user;
    pmx_mutex_unlock(im->mutex);
}

static void wd_set_decide_cb(pmx_backend *self, pmx_decide_fn fn, void *user) {
    wd_impl *im = (wd_impl *)self->impl;
    pmx_mutex_lock(im->mutex);
    im->decide = fn;
    im->decide_user = user;
    pmx_mutex_unlock(im->mutex);
}

static pmx_status wd_apply_decision(pmx_backend *self, const pmx_flow *flow,
                                    const pmx_decision *d) {
    (void)self;
    /* Enforcement already happened inline in the pump; this is just the
     * engine's after-the-fact notification. */
    PMX_LOGD("[backend:windivert] #%llu %s -> %s:%u => %s via %s [%s]",
             (unsigned long long)flow->flow_id, flow->app_name, flow->dst_host,
             (unsigned)flow->dst_port, pmx_verdict_str(d->verdict), d->via_label,
             d->rule_name);
    return PMX_OK;
}

static void wd_destroy(pmx_backend *self) {
    if (self == NULL) {
        return;
    }
    wd_stop(self);
    wd_impl *im = (wd_impl *)self->impl;
    if (im != NULL) {
        pmx_mutex_destroy(im->mutex);
        free(im);
    }
    free(self);
}

pmx_backend *pmx_backend_windivert_create(void) {
    pmx_backend *b = (pmx_backend *)calloc(1, sizeof(*b));
    wd_impl *im = (wd_impl *)calloc(1, sizeof(*im));
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
    im->block_when_cannot_proxy = true;
    im->own_pid = GetCurrentProcessId();
    b->name = "windivert";
    b->impl = im;
    b->caps.per_app = true;    /* exact PID attribution from the driver */
    b->caps.can_block = true;  /* non-sniff handle: we can drop connects */
    b->caps.killswitch = false;
    b->caps.real = false;      /* still cannot redirect a flow to a proxy */
    /* The SOCKET layer reports the remote ADDRESS; the app already resolved the
     * name itself, so we can only ever format a numeric literal into dst_host.
     * Rules that glob a host NAME therefore cannot match here. */
    b->caps.host_names = false;
    b->start = wd_start;
    b->stop = wd_stop;
    b->is_active = wd_is_active;
    b->set_flow_cb = wd_set_flow_cb;
    b->set_decide_cb = wd_set_decide_cb;
    b->apply_decision = wd_apply_decision;
    b->destroy = wd_destroy;
    return b;
}

#else /* !PMX_HAVE_WINDIVERT */

pmx_backend *pmx_backend_windivert_create(void) {
    PMX_LOGI("[backend:windivert] not built. Install the WinDivert SDK under "
             "third_party/windivert and re-run CMake to enable real per-app "
             "monitoring and blocking (see docs/SETUP-WINDIVERT.md).");
    return NULL;
}

#endif
