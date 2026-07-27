#include "pmx_test.h"
#include "proximight/pmx_rule.h"
#include "proximight/pmx_profile.h"
#include "proximight/pmx_engine.h"
#include "proximight/pmx_log.h"

#include <string.h>

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    /* Glob matching. */
    CHECK(pmx_glob_match("*.exe", "chrome.exe", true));
    CHECK(!pmx_glob_match("*.exe", "chrome.com", true));
    CHECK(pmx_glob_match("chrome.exe", "CHROME.EXE", true));
    CHECK(!pmx_glob_match("chrome.exe", "CHROME.EXE", false));
    CHECK(pmx_glob_match("ch?ome*", "chrome-beta", true));
    CHECK(pmx_glob_match("*", "anything", true));

    /* Glob lists. */
    CHECK(pmx_glob_list_match("a; b ; *.exe", "notepad.exe", true));
    CHECK(pmx_glob_list_match("", "anything", true)); /* empty = any */
    CHECK(!pmx_glob_list_match("firefox.exe;msedge.exe", "chrome.exe", true));

    /* Port specs. */
    CHECK(pmx_port_spec_match("80,443,1000-2000", 443));
    CHECK(pmx_port_spec_match("80,443,1000-2000", 1500));
    CHECK(!pmx_port_spec_match("80,443,1000-2000", 3000));
    CHECK(pmx_port_spec_match("", 12345)); /* empty = any */
    CHECK(pmx_port_spec_validate("80,443,1000-2000") == PMX_OK);
    CHECK(pmx_port_spec_validate("80,,-bad") == PMX_ERR_PARSE);

    /* Spaces around the dash must still mean a RANGE. Regression: "8000 - 8080"
     * used to match only the two endpoints, so a Block rule on that spec let
     * :8050 straight out. match() and validate() must agree. */
    CHECK(pmx_port_spec_match("8000 - 8080", 8050));
    CHECK(pmx_port_spec_match("8000 - 8080", 8000));
    CHECK(pmx_port_spec_match("8000 - 8080", 8080));
    CHECK(!pmx_port_spec_match("8000 - 8080", 8081));
    CHECK(pmx_port_spec_validate("8000 - 8080") == PMX_OK);
    CHECK(pmx_port_spec_match("8000- 8080", 8050));
    CHECK(pmx_port_spec_match("8000 -8080", 8050));
    CHECK(pmx_port_spec_validate("8000 -8080") == PMX_OK);
    CHECK(pmx_port_spec_match("80, 443, 1000 - 2000", 1500));

    /* Host patterns that can only ever match a NAME. A backend reporting just
     * numeric addresses can never satisfy these, so the UI/engine warn instead
     * of letting the rule fail silently. */
    CHECK(pmx_host_pattern_needs_names("*.example.com"));
    CHECK(pmx_host_pattern_needs_names("localhost"));
    CHECK(pmx_host_pattern_needs_names("*.local"));
    CHECK(pmx_host_pattern_needs_names("10.*;*.evil.net")); /* any segment */
    CHECK(!pmx_host_pattern_needs_names("10.*"));
    CHECK(!pmx_host_pattern_needs_names("192.168.1.5"));
    CHECK(!pmx_host_pattern_needs_names("127.*;10.*;192.168.*"));
    CHECK(!pmx_host_pattern_needs_names("*"));
    CHECK(!pmx_host_pattern_needs_names(""));
    CHECK(!pmx_host_pattern_needs_names(NULL));
    /* IPv6 literals are hex, so letters there are not a name. */
    CHECK(!pmx_host_pattern_needs_names("fe80::*"));
    CHECK(!pmx_host_pattern_needs_names("2001:db8::1"));

    /* A freshly created rule must be INERT: it has empty patterns, so it
     * matches every connection. Defaulting to PROXY with no target made it
     * resolve to "proxy via nothing" the moment it was added. */
    pmx_rule fresh;
    pmx_rule_init(&fresh);
    CHECK_EQ_INT(fresh.action, PMX_ACTION_DIRECT);
    CHECK_EQ_INT(fresh.target_kind, PMX_TARGET_NONE);

    /* Rule matching. */
    pmx_rule r;
    pmx_rule_init(&r);
    pmx_strlcpy(r.app_pattern, "chrome.exe", sizeof(r.app_pattern));
    pmx_conn_query q1 = {"chrome.exe", "C:\\x\\chrome.exe", "example.com", 443};
    pmx_conn_query q2 = {"firefox.exe", "C:\\x\\firefox.exe", "example.com", 443};
    CHECK(pmx_rule_matches(&r, &q1));
    CHECK(!pmx_rule_matches(&r, &q2));

    /* End-to-end resolution against a profile. */
    pmx_profile pf;
    pmx_profile_init(&pf);
    pmx_proxy *p = pmx_profile_add_proxy(&pf);
    pmx_strlcpy(p->label, "P1", sizeof(p->label));
    pmx_rule *ru = pmx_profile_add_rule(&pf);
    pmx_strlcpy(ru->name, "browsers", sizeof(ru->name));
    pmx_strlcpy(ru->app_pattern, "chrome.exe", sizeof(ru->app_pattern));
    ru->action = PMX_ACTION_PROXY;
    ru->target_kind = PMX_TARGET_PROXY;
    ru->target_id = p->id;
    pf.default_rule.action = PMX_ACTION_DIRECT;

    pmx_decision d1 = pmx_resolve_with_profile(&pf, &q1);
    CHECK_EQ_INT(d1.verdict, PMX_VERDICT_PROXY);
    CHECK_EQ_INT(d1.target_id, p->id);
    CHECK_STR_EQ(d1.rule_name, "browsers");

    pmx_decision d2 = pmx_resolve_with_profile(&pf, &q2);
    CHECK_EQ_INT(d2.verdict, PMX_VERDICT_DIRECT);
    CHECK_STR_EQ(d2.rule_name, "Default");

    /* A disabled rule is skipped. */
    ru->enabled = false;
    pmx_decision d3 = pmx_resolve_with_profile(&pf, &q1);
    CHECK_EQ_INT(d3.verdict, PMX_VERDICT_DIRECT);

    pmx_profile_free(&pf);
    return pmx_test_report();
}
