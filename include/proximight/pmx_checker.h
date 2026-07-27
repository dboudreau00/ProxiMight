/*
 * pmx_checker.h — proxy health checking, synchronous and async.
 *
 * A check does: TCP connect (latency), proxy handshake to a probe target, and
 * optionally an egress-IP lookup through the proxy. Chains can be checked
 * hop-by-hop so a broken link is pinpointed.
 *
 * The synchronous API is what tests and worker threads call. The async
 * pmx_checker runs a background worker so the GUI never blocks; the GUI submits
 * jobs and polls results each frame.
 */
#ifndef PROXIMIGHT_PMX_CHECKER_H
#define PROXIMIGHT_PMX_CHECKER_H

#include "proximight/pmx_proxy.h"
#include "proximight/pmx_chain.h"

PMX_BEGIN_DECLS

typedef struct pmx_check_opts {
    char probe_host[PMX_MAX_HOST]; /* target to CONNECT to through the proxy */
    pmx_port probe_port;           /* usually 443 or 80                      */
    int timeout_ms;                /* per-stage timeout                      */
    bool measure_egress_ip;        /* do an IP-echo HTTP GET through proxy    */
    char egress_service[PMX_MAX_HOST]; /* host serving a plain-text IP        */
    char egress_path[128];             /* request path, e.g. "/"              */
    bool measure_ping;             /* ICMP round-trip to the proxy host       */
} pmx_check_opts;

/* Fill opts with defaults (probe example.com:443, 5s timeout, egress off). */
void pmx_check_opts_defaults(pmx_check_opts *opts);

typedef struct pmx_check_result {
    pmx_id proxy_id;      /* which proxy this result is for               */
    int hop_index;        /* -1 for a whole-proxy check, else the hop     */
    bool reachable;       /* TCP connect to the proxy succeeded           */
    bool handshake_ok;    /* proxy negotiated a tunnel to the probe        */
    int latency_ms;       /* connect+handshake round trip, -1 if n/a       */
    int ping_ms;          /* ICMP round-trip to the proxy host, -1 if n/a  */
    pmx_status status;    /* overall status code                          */
    char egress_ip[PMX_MAX_IP]; /* if measured; else empty                 */
    char message[PMX_MAX_MSG];  /* short human summary (secret-free)        */
    uint64_t checked_at_ms;     /* pmx_now_ms() at completion               */
} pmx_check_result;

/* Synchronous single-proxy check. Blocking, bounded by opts->timeout_ms. */
pmx_status pmx_check_proxy(const pmx_proxy *p, const pmx_check_opts *opts,
                           pmx_check_result *out);

/* ---- async checker ----------------------------------------------------- */

typedef struct pmx_checker pmx_checker;

pmx_checker *pmx_checker_create(const pmx_check_opts *opts);
void pmx_checker_destroy(pmx_checker *chk); /* stops the worker, then frees */

void pmx_checker_set_opts(pmx_checker *chk, const pmx_check_opts *opts);

/* Queue a check for one proxy (a copy is taken). */
pmx_status pmx_checker_submit(pmx_checker *chk, const pmx_proxy *p);

/* Queue a per-hop check of a chain: each hop yields its own result (hop_index
 * set). `proxies`/`count` supply the proxy definitions the hop ids resolve to. */
pmx_status pmx_checker_submit_chain(pmx_checker *chk, const pmx_chain *c,
                                    const pmx_proxy *proxies, size_t count);

/* Dequeue one finished result if available. Returns true and fills *out, or
 * false if the result queue is empty. Non-blocking; call each GUI frame. */
bool pmx_checker_poll(pmx_checker *chk, pmx_check_result *out);

/* Number of jobs still queued/in-flight (for a progress indicator). */
size_t pmx_checker_pending(pmx_checker *chk);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_CHECKER_H */
