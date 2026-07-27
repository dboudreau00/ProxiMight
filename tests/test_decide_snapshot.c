/*
 * test_decide_snapshot.c — the engine's thread-safe decision path.
 *
 * Backends need a verdict the instant the OS reports a connection, from their
 * own thread. The engine answers from a snapshot of the profile that is
 * republished once per pump. This test pins down that contract:
 *
 *   - decide() agrees with the single-threaded resolver
 *   - edits to the live profile are NOT visible to decide() until a pump
 *     (that isolation is exactly what makes it safe to read off-thread)
 *   - after a pump, the new rules take effect
 */
#include "pmx_test.h"
#include "proximight/pmx_engine.h"
#include "proximight/pmx_log.h"

#include <string.h>

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    pmx_engine *e = pmx_engine_create();
    CHECK(e != NULL);
    if (e == NULL) {
        return pmx_test_report();
    }
    pmx_profile *pf = pmx_engine_profile(e);
    CHECK(pf != NULL);

    /* The seeded profile routes browsers through the Tor proxy. */
    pmx_flow f;
    memset(&f, 0, sizeof(f));
    pmx_strlcpy(f.app_name, "chrome.exe", sizeof(f.app_name));
    pmx_strlcpy(f.app_path, "C:\\Apps\\chrome.exe", sizeof(f.app_path));
    pmx_strlcpy(f.dst_host, "example.com", sizeof(f.dst_host));
    f.dst_port = 443;

    pmx_decision d;
    pmx_engine_decide(e, &f, &d);
    CHECK_EQ_INT(d.verdict, PMX_VERDICT_PROXY);

    /* It must agree with the direct resolver. */
    pmx_conn_query q;
    q.app_name = f.app_name;
    q.app_path = f.app_path;
    q.host = f.dst_host;
    q.port = f.dst_port;
    pmx_decision direct = pmx_engine_resolve(e, &q);
    CHECK_EQ_INT(direct.verdict, d.verdict);
    CHECK_STR_EQ(direct.rule_name, d.rule_name);

    /* Mutate the live profile: the snapshot must still hold the old answer. */
    for (size_t i = 0; i < pf->rule_count; i++) {
        pf->rules[i].enabled = false;
    }
    pmx_engine_decide(e, &f, &d);
    CHECK_EQ_INT(d.verdict, PMX_VERDICT_PROXY); /* unchanged until pumped */

    /* ...but the direct resolver, which reads the live profile, sees it now. */
    direct = pmx_engine_resolve(e, &q);
    CHECK_EQ_INT(direct.verdict, PMX_VERDICT_DIRECT);

    /* Pump republishes the snapshot. */
    pmx_engine_pump(e);
    pmx_engine_decide(e, &f, &d);
    CHECK_EQ_INT(d.verdict, PMX_VERDICT_DIRECT);
    CHECK_STR_EQ(d.rule_name, "Default");

    /* A blocking default rule must come through too. */
    pf->default_rule.action = PMX_ACTION_BLOCK;
    pmx_engine_pump(e);
    pmx_engine_decide(e, &f, &d);
    CHECK_EQ_INT(d.verdict, PMX_VERDICT_BLOCK);

    /* NULL-safety: decide must always produce a usable decision. */
    pmx_decision safe;
    pmx_engine_decide(NULL, &f, &safe);
    CHECK_EQ_INT(safe.verdict, PMX_VERDICT_DIRECT);

    pmx_engine_destroy(e);
    return pmx_test_report();
}
