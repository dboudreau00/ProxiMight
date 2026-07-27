/*
 * test_nat.c — the redirection connection table.
 *
 * This is the memory that lets rewritten traffic find its way home. Getting it
 * wrong means replies are attributed to the wrong connection, so it is worth
 * pinning down precisely: replacement on port reuse, expiry, and eviction.
 */
#include "pmx_test.h"
#include "proximight/pmx_nat.h"

#include <string.h>

#define IP(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (d))

int main(void) {
    pmx_nat *n = pmx_nat_create(4, 1000);
    CHECK(n != NULL);
    if (n == NULL) {
        return pmx_test_report();
    }

    const uint32_t local = IP(192, 168, 1, 50);
    CHECK(pmx_nat_add(n, local, 52344, IP(93, 184, 216, 34), 443, 1000) == PMX_OK);
    CHECK(pmx_nat_add(n, local, 52345, IP(1, 1, 1, 1), 80, 1000) == PMX_OK);
    CHECK_EQ_INT(pmx_nat_count(n), 2);

    pmx_nat_entry e;
    CHECK(pmx_nat_find(n, 52344, 1100, &e));
    CHECK_EQ_INT(e.orig_dst_addr, IP(93, 184, 216, 34));
    CHECK_EQ_INT(e.orig_dst_port, 443);
    CHECK_EQ_INT(e.src_addr, local);

    CHECK(pmx_nat_find(n, 52345, 1100, &e));
    CHECK_EQ_INT(e.orig_dst_port, 80);

    /* Unknown port: the rewriter must not invent a destination. */
    CHECK(!pmx_nat_find(n, 9999, 1100, &e));

    /* The OS reuses source ports; a re-add must replace, never duplicate. */
    CHECK(pmx_nat_add(n, local, 52344, IP(10, 0, 0, 7), 8080, 1200) == PMX_OK);
    CHECK_EQ_INT(pmx_nat_count(n), 2);
    CHECK(pmx_nat_find(n, 52344, 1250, &e));
    CHECK_EQ_INT(e.orig_dst_addr, IP(10, 0, 0, 7));
    CHECK_EQ_INT(e.orig_dst_port, 8080);

    /* Explicit removal. */
    pmx_nat_remove(n, 52345);
    CHECK_EQ_INT(pmx_nat_count(n), 1);
    CHECK(!pmx_nat_find(n, 52345, 1250, &e));

    /* Expiry: a dropped SYN must not leak a slot forever. */
    CHECK(pmx_nat_find(n, 52344, 2100, &e));   /* 900ms old, still valid */
    CHECK(!pmx_nat_find(n, 52344, 5000, &e));  /* past the 1000ms TTL     */
    CHECK_EQ_INT(pmx_nat_expire(n, 5000), 1);
    CHECK_EQ_INT(pmx_nat_count(n), 0);

    pmx_nat_destroy(n);

    /* Capacity pressure: NEVER evict a live entry. Evicting the oldest would be a
     * leak — for a long-lived flow the oldest entry is an ACTIVE connection, and
     * dropping its mapping sends its packets out unproxied. A full table of live
     * flows fails closed (block the new connection); expired slots and
     * explicitly-removed slots (a flow whose relay connection ended) reclaim. */
    pmx_nat *small = pmx_nat_create(2, 60000);
    CHECK(small != NULL);
    if (small != NULL) {
        CHECK(pmx_nat_add(small, local, 100, IP(8, 8, 8, 8), 53, 1000) == PMX_OK);
        CHECK(pmx_nat_add(small, local, 101, IP(8, 8, 4, 4), 53, 1000) == PMX_OK);

        /* Full of LIVE entries -> fail closed, both originals left intact. */
        CHECK(pmx_nat_add(small, local, 102, IP(9, 9, 9, 9), 53, 2000) ==
              PMX_ERR_STATE);
        CHECK_EQ_INT(pmx_nat_count(small), 2);
        CHECK(pmx_nat_find(small, 100, 2000, &e));
        CHECK_EQ_INT(e.orig_dst_addr, IP(8, 8, 8, 8));
        CHECK(pmx_nat_find(small, 101, 2000, &e));
        CHECK(!pmx_nat_find(small, 102, 2000, &e));

        /* A flow whose relay side ENDED must keep its mapping — the app's socket
         * may still be open, and the redirect layer rewrites only on a find()
         * hit, so dropping it here would send the next packet DIRECT to the real
         * destination. It must still be reclaimable under pressure, though. */
        pmx_nat_mark_closed(small, 100);
        CHECK(pmx_nat_find(small, 100, 2000, &e)); /* still rewritten! */
        CHECK_EQ_INT(e.orig_dst_addr, IP(8, 8, 8, 8));
        /* ...and being closed, its slot may now be taken by a new flow rather
         * than the table failing closed. */
        CHECK(pmx_nat_add(small, local, 104, IP(5, 5, 5, 5), 53, 2050) == PMX_OK);
        CHECK(pmx_nat_find(small, 104, 2060, &e));
        CHECK_EQ_INT(e.orig_dst_addr, IP(5, 5, 5, 5));
        /* The reused slot is live again, so the table fails closed once more. */
        CHECK(pmx_nat_add(small, local, 105, IP(6, 6, 6, 6), 53, 2070) ==
              PMX_ERR_STATE);
        pmx_nat_remove(small, 104);
        CHECK(pmx_nat_add(small, local, 100, IP(8, 8, 8, 8), 53, 2080) == PMX_OK);

        /* An explicit remove still frees a slot immediately. */
        pmx_nat_remove(small, 100);
        CHECK(pmx_nat_add(small, local, 102, IP(9, 9, 9, 9), 53, 2100) == PMX_OK);
        CHECK(pmx_nat_find(small, 102, 2200, &e));
        CHECK_EQ_INT(e.orig_dst_addr, IP(9, 9, 9, 9));

        /* An expired entry's slot is reclaimable too (past the 60s TTL). */
        CHECK(pmx_nat_add(small, local, 103, IP(1, 2, 3, 4), 53, 70000) == PMX_OK);
        CHECK(pmx_nat_find(small, 103, 70100, &e));
        CHECK_EQ_INT(e.orig_dst_addr, IP(1, 2, 3, 4));

        pmx_nat_destroy(small);
    }

    /* Regression: a LIVE flow must not lose its mapping just because it has
     * outlived the TTL.
     *
     * Expiry used to be measured from the CONNECT (e.created_ms) and nothing
     * refreshed it, so EVERY proxied connection lasting longer than ttl_ms
     * silently stopped being rewritten — and an unmapped flow is not blocked, it
     * egresses DIRECT to the real destination from the real source IP. That is
     * precisely the bypass the eviction policy above is written to prevent,
     * reached through the clock instead of through eviction. Expiry now tracks
     * inactivity, and a lookup counts as activity. */
    pmx_nat *live = pmx_nat_create(4, 1000);
    CHECK(live != NULL);
    if (live != NULL) {
        CHECK(pmx_nat_add(live, local, 6000, IP(93, 184, 216, 34), 443, 0) ==
              PMX_OK);
        /* Poll it every 900ms — what the redirect layer does for every packet of
         * a long download — for many multiples of the TTL. Under the old
         * age-based rule this failed on the second iteration. */
        uint64_t t = 0;
        for (int i = 0; i < 20; i++) {
            t += 900;
            CHECK(pmx_nat_find(live, 6000, t, &e));
            CHECK_EQ_INT(e.orig_dst_addr, IP(93, 184, 216, 34));
            CHECK_EQ_INT(e.orig_dst_port, 443);
        }
        /* 18x the TTL of continuous use, still mapped. */
        CHECK_EQ_INT(pmx_nat_count(live), 1);
        /* Go quiet and it expires on schedule — the dropped-SYN case still works. */
        CHECK(!pmx_nat_find(live, 6000, t + 1001, &e));

        /* A CLOSED flow is NOT kept alive by lookups. Its mapping still matches
         * (late packets go to the relay, never direct) but it must stay
         * reclaimable, or a dead flow could pin its slot forever. */
        CHECK(pmx_nat_add(live, local, 6001, IP(1, 1, 1, 1), 80, 100000) == PMX_OK);
        pmx_nat_mark_closed(live, 6001);
        CHECK(pmx_nat_find(live, 6001, 100500, &e)); /* still rewritten */
        CHECK_EQ_INT(e.orig_dst_port, 80);
        /* That hit must NOT have refreshed it: measured from the add, not from
         * the lookup, this is past the TTL. */
        CHECK(!pmx_nat_find(live, 6001, 101200, &e));

        pmx_nat_destroy(live);
    }

    return pmx_test_report();
}
