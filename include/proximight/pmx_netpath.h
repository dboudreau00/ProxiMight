/*
 * pmx_netpath.h — ICMP latency and MTR-style per-hop path analysis.
 *
 * Two things the proxy checker needs beyond "did the handshake work":
 *   - pmx_ping()  : round-trip latency to a host (ICMP echo)
 *   - pmx_mtr()   : a traceroute that keeps per-hop loss/best/avg/worst, the
 *                   way mtr does, so you can see *where* a path degrades
 *
 * On Windows this uses the IP Helper ICMP API (IcmpSendEcho), which does NOT
 * require Administrator — unlike raw sockets. Other platforms return
 * PMX_ERR_UNSUPPORTED for now (raw ICMP there needs root).
 *
 * IMPORTANT INTERPRETATION NOTE
 * -----------------------------
 * ICMP measures the path from THIS machine to the target. It does not and
 * cannot travel through a SOCKS/HTTP proxy (those carry TCP, not ICMP). So a
 * path report tells you about your own network and your route to the proxy —
 * it is NOT the route your proxied traffic takes after the proxy. The UI says
 * this too, so nobody reads a clean hop list as proof their traffic is private.
 */
#ifndef PROXIMIGHT_PMX_NETPATH_H
#define PROXIMIGHT_PMX_NETPATH_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

#define PMX_MAX_HOPS 30

typedef struct pmx_path_opts {
    int max_hops;       /* stop after this many hops (default 30)        */
    int cycles;         /* probes per hop, for loss/avg (default 3)      */
    int timeout_ms;     /* per probe (default 1000)                      */
    int payload_size;   /* ICMP payload bytes (default 32)               */
    bool resolve_names; /* reverse-DNS each hop (slower; default false)  */
} pmx_path_opts;

void pmx_path_opts_defaults(pmx_path_opts *out);

/* ---- single echo ------------------------------------------------------- */

typedef struct pmx_ping_result {
    bool reachable;         /* an echo reply came back                   */
    int rtt_ms;             /* round trip, -1 if none                    */
    char addr[PMX_MAX_IP];  /* who replied                               */
    pmx_status status;
} pmx_ping_result;

/* One ICMP echo. `ttl` 0 uses the system default. Blocking, bounded by
 * timeout_ms. */
pmx_status pmx_ping(const char *host, int ttl, int timeout_ms,
                    pmx_ping_result *out);

/* ---- MTR-style path ---------------------------------------------------- */

typedef struct pmx_hop {
    int ttl;                 /* hop number (1-based)                      */
    char addr[PMX_MAX_IP];   /* responding router, empty if none replied  */
    char name[PMX_MAX_HOST]; /* reverse DNS, empty unless resolve_names    */
    int sent;
    int recv;
    int best_ms;
    int worst_ms;
    double avg_ms;
    double loss_pct;
    bool is_dest;            /* this hop is the target itself             */
} pmx_hop;

typedef struct pmx_mtr_result {
    char target[PMX_MAX_HOST];
    char target_addr[PMX_MAX_IP];
    pmx_hop hops[PMX_MAX_HOPS];
    size_t hop_count;
    bool reached;    /* the destination answered                          */
    pmx_status status;
} pmx_mtr_result;

/* Walk the path with increasing TTL, probing each hop `cycles` times.
 * Blocking; can take max_hops * cycles * timeout_ms in the worst case. */
pmx_status pmx_mtr(const char *host, const pmx_path_opts *opts,
                   pmx_mtr_result *out);

/* ---- async wrapper (the GUI must never block) -------------------------- */

typedef struct pmx_mtr_job pmx_mtr_job;

/* Start a path scan on a worker thread. Returns NULL on failure. */
pmx_mtr_job *pmx_mtr_start(const char *host, const pmx_path_opts *opts);

/* True once finished; *out receives the result (valid only when true). */
bool pmx_mtr_done(pmx_mtr_job *job, pmx_mtr_result *out);

/* Hop currently being probed, for a progress indicator (0 until started). */
int pmx_mtr_progress(pmx_mtr_job *job);

/* Stop (if running) and free. Safe at any time. */
void pmx_mtr_free(pmx_mtr_job *job);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_NETPATH_H */
