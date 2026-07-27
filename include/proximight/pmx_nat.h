/*
 * pmx_nat.h — the connection table behind transparent redirection.
 *
 * When ProxiMight decides a connection should be proxied, it rewrites the
 * outbound packet's destination to the local relay. To put the reply traffic
 * back the way the application expects, it has to remember what the original
 * destination was. That memory is this table, keyed by the connection's source
 * port (which is unique per local TCP connection).
 *
 *   outbound  app:52344 -> 93.184.216.34:443
 *             rewritten to 127.0.0.1:<relay>      [remember 52344 -> 93.184…:443]
 *   inbound   127.0.0.1:<relay> -> app:52344
 *             rewritten to appear as 93.184.216.34:443 -> app:52344
 *
 * The application never sees the substitution.
 *
 * Entries expire on INACTIVITY: a SYN that is dropped, or a flow the redirect
 * layer never sees close, must not leak a slot forever — but a flow that is
 * still passing traffic must never lose its mapping, because an unmapped flow is
 * not blocked, it egresses direct. Addresses are host byte order.
 *
 * This is deliberately a standalone, side-effect-free module so the logic can
 * be unit tested without a driver.
 */
#ifndef PROXIMIGHT_PMX_NAT_H
#define PROXIMIGHT_PMX_NAT_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef struct pmx_nat_entry {
    uint32_t src_addr; /* host order */
    pmx_port src_port;
    uint32_t orig_dst_addr;
    pmx_port orig_dst_port;
    uint64_t created_ms;
} pmx_nat_entry;

typedef struct pmx_nat pmx_nat;

/* `capacity` entries, each valid for `ttl_ms`. */
pmx_nat *pmx_nat_create(size_t capacity, int ttl_ms);
void pmx_nat_destroy(pmx_nat *n);

/* Remember where this connection was really going. Re-adding the same source
 * port replaces the entry (ports get reused). */
pmx_status pmx_nat_add(pmx_nat *n, uint32_t src_addr, pmx_port src_port,
                       uint32_t orig_dst_addr, pmx_port orig_dst_port,
                       uint64_t now_ms);

/* Copy out the entry for `src_port`, if it hasn't expired.
 *
 * NOT a pure read: a hit on a live entry refreshes its idle timer, because a
 * lookup is precisely the evidence that the flow is still going. Without that,
 * the TTL would kill the mapping of a perfectly healthy long-lived connection
 * and its next packet would egress direct. A `closed` entry is not refreshed —
 * it must stay reclaimable. */
bool pmx_nat_find(pmx_nat *n, pmx_port src_port, uint64_t now_ms,
                  pmx_nat_entry *out);

void pmx_nat_remove(pmx_nat *n, pmx_port src_port);

/* Mark a flow's relay connection as finished WITHOUT dropping the mapping.
 *
 * Deleting it outright would be a leak: the application's socket can still be
 * open (it is only learning about the close now), and the redirect layer
 * rewrites a packet only when pmx_nat_find hits — so the next packet it sends
 * would egress DIRECT to the real destination, from the real source IP. A
 * closed entry therefore keeps matching (traffic keeps going to the relay,
 * which refuses it) but becomes reclaimable, so the table is not wedged by dead
 * flows and pmx_nat_add can still fail closed rather than evict a LIVE one. */
void pmx_nat_mark_closed(pmx_nat *n, pmx_port src_port);

/* Drop everything older than the TTL. Returns how many were dropped. */
size_t pmx_nat_expire(pmx_nat *n, uint64_t now_ms);

size_t pmx_nat_count(pmx_nat *n);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_NAT_H */
