/*
 * pmx_relay.h — the local SOCKSifier that carries redirected connections.
 *
 * This is the second half of real redirection. The flow is:
 *
 *   1. The redirect layer (WinDivert, pf, ...) sees an outbound SYN it has
 *      decided to proxy. It records where the connection was *really* headed
 *      and which proxy to use, keyed by the connection's source port:
 *          pmx_relay_register(relay, src_port, "example.com", 443, &proxy);
 *   2. It then NATs the packet so the connection lands on the relay's loopback
 *      listener instead of the real destination.
 *   3. The relay accepts, looks up the entry by the peer's source port,
 *      connects to the proxy, performs pmx_proxy_handshake() to the original
 *      destination, and splices bytes both ways until either side closes.
 *
 * The application never knows: it thinks it opened a normal socket to the
 * destination. Registrations expire so a dropped SYN can't leak an entry.
 *
 * The relay itself is portable C and independently testable — you can drive it
 * without any driver by registering an entry and connecting from that source
 * port yourself (see tests/test_relay.c).
 */
#ifndef PROXIMIGHT_PMX_RELAY_H
#define PROXIMIGHT_PMX_RELAY_H

#include "proximight/pmx_proxy.h"

PMX_BEGIN_DECLS

typedef struct pmx_relay pmx_relay;

/* Start a loopback TCP relay. `port` 0 picks an ephemeral port. */
pmx_status pmx_relay_start(pmx_relay **out, pmx_port port);

/* Stop accepting, unwind in-flight connections, and free. */
void pmx_relay_stop(pmx_relay *r);

/* The port the relay is listening on (redirect targets point here). */
pmx_port pmx_relay_port(const pmx_relay *r);

/* Record the real destination and the proxy chain for a connection that will
 * arrive from `src_port`. Re-registering the same source port replaces the
 * entry.
 *
 * `chain` is traversed in order: the relay connects to chain[0], then asks each
 * hop to reach the next one, and finally asks the last hop for the real
 * destination. `chain_len` of 1 is the ordinary single-proxy case. */
pmx_status pmx_relay_register(pmx_relay *r, pmx_port src_port,
                              const char *dst_host, pmx_port dst_port,
                              const pmx_proxy *chain, size_t chain_len);

/* Optional: invoked (on a relay worker thread) when a relayed connection ends,
 * with the source port it was registered under. The backend uses this to drop
 * the flow's NAT entry so the table isn't wedged by dead connections — which is
 * what lets pmx_nat_add fail closed on a full table instead of evicting (and
 * silently un-proxying) a live flow. Set it before traffic starts; the callback
 * must be cheap and must not call back into the relay. */
typedef void (*pmx_relay_close_cb)(void *user, pmx_port src_port);
void pmx_relay_set_close_cb(pmx_relay *r, pmx_relay_close_cb cb, void *user);

/* Connections currently being relayed. */
size_t pmx_relay_active(pmx_relay *r);

/* Counters since start: connections successfully proxied, and failures
 * (no registration, proxy unreachable, handshake rejected). */
void pmx_relay_stats(pmx_relay *r, uint64_t *out_ok, uint64_t *out_failed);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_RELAY_H */
