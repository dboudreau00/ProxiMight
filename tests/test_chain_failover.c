#include "pmx_test.h"
#include "proximight/pmx_chain.h"
#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_log.h"
#include "proximight/pmx_profile.h" /* the proxy-delete / chain-integrity case */

#include <stdlib.h>
#include <string.h>

/* A firewall that ACCEPTS the call but fails to engage — what a real WFP
 * backend does when it is not elevated. A NULL firewall alone cannot exercise
 * the engage-failure branches, because production always has a firewall object;
 * it just may not be able to enforce. */
typedef struct failing_fw {
    bool engaged;
    int engage_calls;
} failing_fw;

static pmx_status failing_engage(pmx_firewall *self, const pmx_fw_endpoint *a,
                                 size_t n, const pmx_lockdown_policy *p) {
    (void)a; (void)n; (void)p;
    ((failing_fw *)self->impl)->engage_calls++;
    return PMX_ERR_PERMISSION; /* e.g. "needs Administrator" */
}
static pmx_status failing_disengage(pmx_firewall *self) {
    ((failing_fw *)self->impl)->engaged = false;
    return PMX_OK;
}
static bool failing_is_engaged(pmx_firewall *self) {
    return ((failing_fw *)self->impl)->engaged;
}
static bool failing_requires_priv(pmx_firewall *self) { (void)self; return true; }
static void failing_destroy(pmx_firewall *self) {
    if (self != NULL) { free(self->impl); free(self); }
}
static pmx_firewall *failing_fw_create(void) {
    pmx_firewall *fw = (pmx_firewall *)calloc(1, sizeof(*fw));
    failing_fw *impl = (failing_fw *)calloc(1, sizeof(*impl));
    if (fw == NULL || impl == NULL) { free(fw); free(impl); return NULL; }
    fw->name = "failing";
    fw->impl = impl;
    fw->engage = failing_engage;
    fw->disengage = failing_disengage;
    fw->is_engaged = failing_is_engaged;
    fw->requires_privilege = failing_requires_priv;
    fw->destroy = failing_destroy;
    return fw;
}

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    /* --- chain hop operations --- */
    pmx_chain c;
    pmx_chain_init(&c);
    CHECK(pmx_chain_add_hop(&c, 10) == PMX_OK);
    CHECK(pmx_chain_add_hop(&c, 20) == PMX_OK);
    CHECK(pmx_chain_add_hop(&c, 30) == PMX_OK);
    CHECK_EQ_INT(c.hop_count, 3);
    CHECK(pmx_chain_move_hop(&c, 2, 0) == PMX_OK); /* 30,10,20 */
    CHECK_EQ_INT(c.hops[0], 30);
    CHECK_EQ_INT(c.hops[1], 10);
    CHECK(pmx_chain_remove_hop(&c, 1) == PMX_OK); /* 30,20 */
    CHECK_EQ_INT(c.hop_count, 2);
    CHECK_EQ_INT(c.hops[1], 20);

    /* --- lockdown hysteresis: fail-closed --- */
    pmx_firewall *fw = pmx_firewall_stub_create();
    CHECK(fw != NULL);
    pmx_lockdown_policy pol;
    pmx_lockdown_policy_defaults(&pol);
    pol.mode = PMX_LOCKDOWN_FAIL_CLOSED;
    pol.block_until_verified = false; /* start optimistic (ARMED_HEALTHY) */
    pol.failures_before_trip = 2;
    pol.successes_before_restore = 2;

    pmx_lockdown *ld = pmx_lockdown_create(&pol, fw);
    CHECK(ld != NULL);
    CHECK(pmx_lockdown_arm(ld) == PMX_OK);
    CHECK_EQ_INT(pmx_lockdown_get_state(ld), PMX_LD_ARMED_HEALTHY);
    CHECK(fw->is_engaged(fw)); /* kill switch engaged while armed */

    bool changed = false;
    pmx_lockdown_on_health(ld, false, &changed); /* 1 failure: not enough */
    CHECK_EQ_INT(pmx_lockdown_get_state(ld), PMX_LD_ARMED_HEALTHY);
    pmx_lockdown_on_health(ld, false, &changed); /* 2 failures: trip */
    CHECK_EQ_INT(pmx_lockdown_get_state(ld), PMX_LD_TRIPPED_BLOCKING);
    CHECK(changed);

    pmx_lockdown_on_health(ld, true, &changed);  /* 1 success */
    CHECK_EQ_INT(pmx_lockdown_get_state(ld), PMX_LD_TRIPPED_BLOCKING);
    pmx_lockdown_on_health(ld, true, &changed);  /* 2 successes: restore */
    CHECK_EQ_INT(pmx_lockdown_get_state(ld), PMX_LD_ARMED_HEALTHY);

    pmx_lockdown_disarm(ld);
    CHECK(!fw->is_engaged(fw));
    pmx_lockdown_destroy(ld);

    /* --- fail-open never engages the firewall --- */
    pol.mode = PMX_LOCKDOWN_FAIL_OPEN;
    pmx_lockdown *ld2 = pmx_lockdown_create(&pol, fw);
    pmx_lockdown_arm(ld2);
    CHECK(!fw->is_engaged(fw));
    pmx_lockdown_on_health(ld2, false, &changed);
    pmx_lockdown_on_health(ld2, false, &changed);
    CHECK_EQ_INT(pmx_lockdown_get_state(ld2), PMX_LD_FAILED_OPEN);
    CHECK(!fw->is_engaged(fw)); /* still open */
    pmx_lockdown_destroy(ld2);

    /* --- changing the mode on an ARMED controller must re-apply enforcement ---
     * Regression: set_policy used to only memcpy the policy. Switching to a
     * blocking mode left the state at INACTIVE/FAILED_OPEN, and the trip branch
     * only fires from ARMED_HEALTHY — so the kill switch could never engage,
     * silently, for the rest of the session. */
    pol.mode = PMX_LOCKDOWN_OFF;
    pmx_lockdown *ld3 = pmx_lockdown_create(&pol, fw);
    CHECK(ld3 != NULL);
    CHECK(pmx_lockdown_arm(ld3) == PMX_OK);
    CHECK_EQ_INT(pmx_lockdown_get_state(ld3), PMX_LD_INACTIVE);
    CHECK(!fw->is_engaged(fw));

    /* Off -> fail closed while armed: must engage NOW, not "never". */
    pol.mode = PMX_LOCKDOWN_FAIL_CLOSED;
    pol.block_until_verified = false;
    pmx_lockdown_set_policy(ld3, &pol);
    CHECK(fw->is_engaged(fw));
    CHECK_EQ_INT(pmx_lockdown_get_state(ld3), PMX_LD_ARMED_HEALTHY);
    /* ...and it must still be able to trip afterwards. */
    pmx_lockdown_on_health(ld3, false, &changed);
    pmx_lockdown_on_health(ld3, false, &changed);
    CHECK_EQ_INT(pmx_lockdown_get_state(ld3), PMX_LD_TRIPPED_BLOCKING);

    /* fail closed -> Off while armed: must release the firewall, not strand it
     * engaged with a stale "blocking" label. */
    pol.mode = PMX_LOCKDOWN_OFF;
    pmx_lockdown_set_policy(ld3, &pol);
    CHECK(!fw->is_engaged(fw));
    CHECK_EQ_INT(pmx_lockdown_get_state(ld3), PMX_LD_INACTIVE);
    pmx_lockdown_destroy(ld3);

    /* --- an unrecognized mode must fail CLOSED, never silently "never block" --
     * pmx_profile.c casts the JSON int straight to the enum, so a corrupt or
     * hand-edited profile can carry an out-of-range mode. */
    pmx_lockdown_policy bogus;
    pmx_lockdown_policy_defaults(&bogus);
    bogus.mode = (pmx_lockdown_mode)999;
    bogus.block_until_verified = true;
    pmx_lockdown *ld4 = pmx_lockdown_create(&bogus, fw);
    CHECK(ld4 != NULL);
    CHECK(pmx_lockdown_arm(ld4) == PMX_OK);
    CHECK(fw->is_engaged(fw));
    CHECK_EQ_INT(pmx_lockdown_get_state(ld4), PMX_LD_TRIPPED_BLOCKING);
    pmx_lockdown_disarm(ld4);
    pmx_lockdown_destroy(ld4);

    /* --- a firewall that cannot engage must NOT report a blocking state ------
     * With no firewall object we cannot enforce; arming must say so rather than
     * showing a reassuring "Tripped — blocking" while nothing is blocked. */
    pmx_lockdown_policy fc;
    pmx_lockdown_policy_defaults(&fc);
    fc.mode = PMX_LOCKDOWN_FAIL_CLOSED;
    pmx_lockdown *ld5 = pmx_lockdown_create(&fc, NULL);
    CHECK(ld5 != NULL);
    CHECK(pmx_lockdown_arm(ld5) != PMX_OK);
    CHECK_EQ_INT(pmx_lockdown_get_state(ld5), PMX_LD_FAILED_OPEN);
    pmx_lockdown_destroy(ld5);

    /* The realistic version of the same hazard: a firewall that EXISTS but
     * cannot enforce (real WFP without Administrator). Arming, and tripping
     * on health failures, must both report FAILED_OPEN rather than a
     * reassuring "blocking" — otherwise the UI shows a red shield while
     * nothing is blocked. */
    pmx_firewall *bad = failing_fw_create();
    CHECK(bad != NULL);
    if (bad != NULL) {
        pmx_lockdown_policy fp;
        pmx_lockdown_policy_defaults(&fp);
        fp.mode = PMX_LOCKDOWN_FAIL_CLOSED;
        fp.block_until_verified = true;
        pmx_lockdown *ld6 = pmx_lockdown_create(&fp, bad);
        CHECK(ld6 != NULL);
        CHECK(pmx_lockdown_arm(ld6) != PMX_OK);
        CHECK(!bad->is_engaged(bad));
        CHECK_EQ_INT(pmx_lockdown_get_state(ld6), PMX_LD_FAILED_OPEN);
        pmx_lockdown_destroy(ld6);

        /* And via the on_health TRIP path: start optimistic, then fail. */
        fp.block_until_verified = false;
        pmx_lockdown *ld7 = pmx_lockdown_create(&fp, bad);
        CHECK(ld7 != NULL);
        pmx_lockdown_arm(ld7); /* engage fails -> FAILED_OPEN */
        /* Force the state machine into ARMED_HEALTHY so the trip branch runs. */
        pmx_lockdown_on_health(ld7, true, &changed);
        pmx_lockdown_on_health(ld7, true, &changed);
        CHECK_EQ_INT(pmx_lockdown_get_state(ld7), PMX_LD_ARMED_HEALTHY);
        pmx_lockdown_on_health(ld7, false, &changed);
        pmx_lockdown_on_health(ld7, false, &changed);
        /* Tripped, engage failed -> must NOT claim to be blocking. */
        CHECK_EQ_INT(pmx_lockdown_get_state(ld7), PMX_LD_FAILED_OPEN);
        CHECK(!bad->is_engaged(bad));
        pmx_lockdown_destroy(ld7);
        bad->destroy(bad);
    }

    /* Deleting a proxy must never silently SHORTEN a sequential chain.
     *
     * The hops of a sequential chain are a path: their number and order are the
     * protection the user asked for. Compacting a deleted hop out would turn a
     * 3-hop chain into a 2-hop one and route traffic through less protection than
     * requested, with nothing said about it. The reference is left dangling so the
     * resolver's all-or-nothing rule fails the flow closed and the editor shows a
     * "(missing proxy)" hop. A redundancy chain is an unordered SET, so there
     * compacting is the correct behaviour. */
    {
        pmx_profile pf;
        pmx_profile_init(&pf);

        pmx_proxy *px_a = pmx_profile_add_proxy(&pf);
        pmx_proxy *px_b = pmx_profile_add_proxy(&pf);
        pmx_proxy *px_c = pmx_profile_add_proxy(&pf);
        CHECK(px_a != NULL && px_b != NULL && px_c != NULL);
        if (px_a != NULL && px_b != NULL && px_c != NULL) {
            pmx_id ia = px_a->id, ib = px_b->id, ic = px_c->id;

            pmx_chain *seq = pmx_profile_add_chain(&pf);
            CHECK(seq != NULL);
            if (seq != NULL) {
                seq->mode = PMX_CHAIN_SEQUENTIAL;
                pmx_chain_add_hop(seq, ia);
                pmx_chain_add_hop(seq, ib);
                pmx_chain_add_hop(seq, ic);
                CHECK_EQ_INT(seq->hop_count, 3);
            }
            pmx_chain *red = pmx_profile_add_chain(&pf);
            CHECK(red != NULL);
            if (red != NULL) {
                red->mode = PMX_CHAIN_REDUNDANCY;
                pmx_chain_add_hop(red, ia);
                pmx_chain_add_hop(red, ib);
                pmx_chain_add_hop(red, ic);
                CHECK_EQ_INT(red->hop_count, 3);
            }

            CHECK(pmx_profile_remove_proxy(&pf, ib) == PMX_OK);

            /* Sequential: same LENGTH, middle hop now unresolvable. */
            seq = pmx_profile_find_chain(&pf, pf.chains[0].id);
            CHECK(seq != NULL);
            if (seq != NULL) {
                CHECK_EQ_INT(seq->hop_count, 3);
                CHECK_EQ_INT(seq->hops[0], ia);
                CHECK_EQ_INT(seq->hops[1], PMX_ID_NONE);
                CHECK_EQ_INT(seq->hops[2], ic);
                CHECK(pmx_profile_find_proxy(&pf, seq->hops[1]) == NULL);
            }
            /* Redundancy: a set, so it legitimately shrinks. */
            red = pmx_profile_find_chain(&pf, pf.chains[1].id);
            CHECK(red != NULL);
            if (red != NULL) {
                CHECK_EQ_INT(red->hop_count, 2);
                CHECK_EQ_INT(red->hops[0], ia);
                CHECK_EQ_INT(red->hops[1], ic);
            }
        }
        pmx_profile_free(&pf);
    }

    fw->destroy(fw);
    return pmx_test_report();
}
