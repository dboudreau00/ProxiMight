/*
 * pmx_rule.h — proxification rules and their matching, à la Proxifier.
 *
 * The engine walks a profile's rules top to bottom; the first ENABLED rule
 * whose criteria all match decides the action. If none match, the profile's
 * default rule applies. Ordering is significant — the GUI lets you drag to
 * reorder.
 */
#ifndef PROXIMIGHT_PMX_RULE_H
#define PROXIMIGHT_PMX_RULE_H

#include "proximight/pmx_types.h"
#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef enum pmx_action {
    PMX_ACTION_DIRECT = 0, /* connect straight out, no proxy   */
    PMX_ACTION_PROXY,      /* route via target proxy or chain  */
    PMX_ACTION_BLOCK,      /* refuse the connection            */
    PMX_ACTION__COUNT
} pmx_action;

typedef enum pmx_target_kind {
    PMX_TARGET_NONE = 0, /* for DIRECT / BLOCK               */
    PMX_TARGET_PROXY,    /* target_id refers to a pmx_proxy  */
    PMX_TARGET_CHAIN     /* target_id refers to a pmx_chain  */
} pmx_target_kind;

typedef struct pmx_rule {
    pmx_id id;
    char name[PMX_MAX_NAME];
    bool enabled;

    /* Match criteria. An empty pattern means "any" for that dimension.
     * app_pattern matches the application's file name or full path;
     * host_pattern matches the target hostname/IP. Both are ';'-separated
     * lists of case-insensitive globs (* and ?). port_spec is like
     * "80,443,8000-8080"; empty means any port. */
    char app_pattern[PMX_MAX_PATTERN];
    char host_pattern[PMX_MAX_PATTERN];
    char port_spec[PMX_MAX_PORTSPEC];

    pmx_action action;
    pmx_target_kind target_kind;
    pmx_id target_id; /* proxy or chain id when action == PMX_ACTION_PROXY */
} pmx_rule;

/* A connection to be classified. */
typedef struct pmx_conn_query {
    const char *app_name; /* e.g. "chrome.exe"        (may be NULL) */
    const char *app_path; /* full path                (may be NULL) */
    const char *host;     /* target hostname or IP    (may be NULL) */
    pmx_port port;        /* target port                            */
} pmx_conn_query;

void pmx_rule_init(pmx_rule *r);
const char *pmx_action_str(pmx_action a); /* "Direct" / "Proxy" / "Block" */

/* True if every non-empty criterion in `r` matches `q`. Ignores r->enabled. */
bool pmx_rule_matches(const pmx_rule *r, const pmx_conn_query *q);

/* ---- matching primitives (exposed for reuse + tests) ------------------- */

/* Glob match with '*' and '?'. If ci, comparison is case-insensitive. */
bool pmx_glob_match(const char *pattern, const char *text, bool ci);

/* Match `text` against a ';'-separated list of globs. Empty/NULL list => true
 * (i.e. "any"). */
bool pmx_glob_list_match(const char *list, const char *text, bool ci);

/* Match a port against a spec like "80,443,1000-2000". Empty/NULL => true. */
bool pmx_port_spec_match(const char *spec, pmx_port port);

/* Validate a port spec string. PMX_OK or PMX_ERR_PARSE. */
pmx_status pmx_port_spec_validate(const char *spec);

/* True if any segment of this ';'-separated host pattern can only ever match a
 * host NAME — i.e. it contains a letter, so no numeric IPv4/IPv6 literal can
 * satisfy it ("*.example.com" yes; "10.*", "192.168.1.5", "*" no).
 *
 * Why this exists: `host_pattern` is globbed against `pmx_flow.dst_host`, and a
 * backend whose caps.host_names is false only ever puts a numeric literal
 * there (the application resolved the name itself before connecting). Such a
 * rule then silently never matches — traffic escapes a Block/Proxy rule that
 * looks active in the UI. Callers use this to warn instead of failing quietly. */
bool pmx_host_pattern_needs_names(const char *pattern);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_RULE_H */
