#include "pmx_test.h"
#include "proximight/pmx_profile.h"
#include "proximight/pmx_log.h"

#include <string.h>

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    pmx_profile a;
    pmx_profile_seed_defaults(&a);

    /* The shipped profile must not rely on host NAMES: a real redirection
     * backend sees the connect after the app resolved the name, so it only
     * reports a numeric address and a name pattern would silently never fire. */
    for (size_t i = 0; i < a.rule_count; i++) {
        CHECK(!pmx_host_pattern_needs_names(a.rules[i].host_pattern));
    }

    /* Add a proxy with credentials to exercise auth round-tripping. */
    pmx_proxy *p = pmx_profile_add_proxy(&a);
    CHECK(p != NULL);
    pmx_strlcpy(p->label, "Auth SOCKS", sizeof(p->label));
    p->type = PMX_PROXY_SOCKS5;
    pmx_strlcpy(p->host, "proxy.example.net", sizeof(p->host));
    p->port = 1080;
    p->use_auth = true;
    pmx_strlcpy(p->username, "alice", sizeof(p->username));
    pmx_strlcpy(p->password, "s3cr3t", sizeof(p->password));

    size_t proxies = a.proxy_count, rules = a.rule_count, chains = a.chain_count;
    pmx_id auth_id = p->id;

    char *json = NULL;
    CHECK(pmx_profile_to_json(&a, &json) == PMX_OK);
    CHECK(json != NULL);

    pmx_profile b;
    pmx_profile_init(&b);
    CHECK(pmx_profile_from_json(&b, json) == PMX_OK);

    CHECK_EQ_INT(b.proxy_count, proxies);
    CHECK_EQ_INT(b.rule_count, rules);
    CHECK_EQ_INT(b.chain_count, chains);
    CHECK_STR_EQ(b.label, a.label);

    const pmx_proxy *bp = pmx_profile_find_proxy_c(&b, auth_id);
    CHECK(bp != NULL);
    if (bp != NULL) {
        CHECK_STR_EQ(bp->host, "proxy.example.net");
        CHECK_EQ_INT(bp->type, PMX_PROXY_SOCKS5);
        CHECK(bp->use_auth == true);
        CHECK_STR_EQ(bp->username, "alice");
        CHECK_STR_EQ(bp->password, "s3cr3t");
    }

    /* next_id must exceed every stored id. */
    CHECK(b.next_id > auth_id);

    /* Rejecting non-profile JSON. */
    pmx_profile c;
    pmx_profile_init(&c);
    CHECK(pmx_profile_from_json(&c, "{\"hello\":true}") == PMX_ERR_PARSE);

    pmx_profile_string_free(json);
    pmx_profile_free(&a);
    pmx_profile_free(&b);
    pmx_profile_free(&c);
    return pmx_test_report();
}
