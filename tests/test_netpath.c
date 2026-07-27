/*
 * test_netpath.c — ICMP latency and MTR-style path analysis.
 *
 * Deliberately loopback-only: the tests must be deterministic and must not
 * depend on (or leak to) the internet.
 */
#include "pmx_test.h"
#include "proximight/pmx_netpath.h"
#include "proximight/pmx_log.h"
#include "proximight/pmx_net.h" /* pmx_sleep_ms — implicitly declared without it,
                                 * and the implicit "returns int" disagrees with
                                 * the real void return. */

#include <string.h>
#include <stdio.h>

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    pmx_path_opts o;
    pmx_path_opts_defaults(&o);
    CHECK_EQ_INT(o.cycles, 3);
    CHECK(o.max_hops > 0 && o.max_hops <= PMX_MAX_HOPS);

#if defined(_WIN32)
    /* Loopback must always answer an echo. */
    pmx_ping_result pr;
    pmx_status st = pmx_ping("127.0.0.1", 0, 1000, &pr);
    CHECK(st == PMX_OK);
    CHECK(pr.reachable);
    CHECK(pr.rtt_ms >= 0);
    CHECK_STR_EQ(pr.addr, "127.0.0.1");

    /* A name that cannot resolve must report DNS failure, not hang. */
    pmx_ping_result bad;
    st = pmx_ping("no-such-host.invalid", 0, 800, &bad);
    CHECK(st == PMX_ERR_DNS);
    CHECK(!bad.reachable);

    /* A path to loopback is exactly one hop, and it is the destination. */
    pmx_path_opts fast;
    pmx_path_opts_defaults(&fast);
    fast.cycles = 2;
    fast.timeout_ms = 800;
    fast.max_hops = 5;

    pmx_mtr_result mr;
    st = pmx_mtr("127.0.0.1", &fast, &mr);
    CHECK(st == PMX_OK);
    CHECK(mr.reached);
    CHECK(mr.hop_count >= 1);
    CHECK_STR_EQ(mr.target_addr, "127.0.0.1");
    if (mr.hop_count >= 1) {
        const pmx_hop *h = &mr.hops[0];
        CHECK_EQ_INT(h->ttl, 1);
        CHECK(h->is_dest);
        CHECK_EQ_INT(h->sent, 2);
        CHECK_EQ_INT(h->recv, 2);
        CHECK(h->loss_pct == 0.0);
        CHECK(h->best_ms >= 0);
        CHECK(h->avg_ms >= 0.0);
        CHECK_STR_EQ(h->addr, "127.0.0.1");
    }

    /* Async wrapper: must finish and agree with the blocking call. */
    pmx_mtr_job *job = pmx_mtr_start("127.0.0.1", &fast);
    CHECK(job != NULL);
    if (job != NULL) {
        /* Zeroed up front. pmx_mtr_done() only writes *out when it returns true
         * and every read below is guarded by `done`, so this is not a real
         * uninitialised use — but the compiler cannot see through that, and the
         * resulting C4701 would fail the build under PMX_WERROR. Zeroing also
         * means a future regression that returned true without filling the struct
         * would show up as a failed CHECK rather than as stack garbage that
         * happened to look plausible. */
        pmx_mtr_result ar;
        memset(&ar, 0, sizeof(ar));
        bool done = false;
        for (int i = 0; i < 200 && !done; i++) { /* <= 10s */
            done = pmx_mtr_done(job, &ar);
            if (!done) {
                pmx_sleep_ms(50);
            }
        }
        CHECK(done);
        if (done) {
            CHECK(ar.reached);
            CHECK(ar.hop_count >= 1);
        }
        pmx_mtr_free(job);
    }

    /* Freeing a job mid-flight must not hang or crash. */
    pmx_mtr_job *job2 = pmx_mtr_start("127.0.0.1", &fast);
    CHECK(job2 != NULL);
    pmx_mtr_free(job2);
#else
    pmx_ping_result pr;
    CHECK(pmx_ping("127.0.0.1", 0, 500, &pr) == PMX_ERR_UNSUPPORTED);
    printf("netpath: ICMP is Windows-only for now; skipped\n");
#endif

    return pmx_test_report();
}
