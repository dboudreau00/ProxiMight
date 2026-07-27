#include "proximight/pmx_profile.h"
#include "proximight/pmx_log.h"
#include "proximight/pmx_protect.h"
#include "pmx_json.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h> /* MoveFileExA — atomic replace, see write_file_atomic */
#endif

/* Grow a dynamic array by doubling. Used only in functions that return a
 * pointer (so a failed realloc can bail with NULL). */
#define PMX_GROW(arrptr, capptr, count, type)                                   \
    do {                                                                        \
        if ((count) >= *(capptr)) {                                             \
            size_t nc = (*(capptr) == 0) ? 8u : (*(capptr) * 2u);               \
            type *np = (type *)realloc(*(arrptr), nc * sizeof(type));           \
            if (np == NULL)                                                     \
                return NULL;                                                    \
            *(arrptr) = np;                                                     \
            *(capptr) = nc;                                                     \
        }                                                                       \
    } while (0)

/* ---------------------------------------------------------------- lifecycle */

void pmx_profile_init(pmx_profile *pf) {
    if (pf == NULL) {
        return;
    }
    memset(pf, 0, sizeof(*pf));
    pf->next_id = 1;
    pmx_rule_init(&pf->default_rule);
    pmx_strlcpy(pf->default_rule.name, "Default", sizeof(pf->default_rule.name));
    pf->default_rule.action = PMX_ACTION_DIRECT;
    pf->default_rule.target_kind = PMX_TARGET_NONE;
    pmx_lockdown_policy_defaults(&pf->lockdown);
    pf->settings.dns_through_proxy = true;
    pf->settings.demo_traffic = true;
    pf->settings.demo_interval_ms = 1500;
    pmx_check_opts_defaults(&pf->settings.check);
    pmx_strlcpy(pf->label, "New profile", sizeof(pf->label));
}

void pmx_profile_clear(pmx_profile *pf) {
    if (pf == NULL) {
        return;
    }
    pf->proxy_count = 0;
    pf->rule_count = 0;
    pf->chain_count = 0;
    pf->vpn_count = 0;
}

void pmx_profile_free(pmx_profile *pf) {
    if (pf == NULL) {
        return;
    }
    free(pf->proxies);
    free(pf->rules);
    free(pf->chains);
    free(pf->vpns);
    memset(pf, 0, sizeof(*pf));
}

pmx_status pmx_profile_copy(pmx_profile *dst, const pmx_profile *src) {
    if (dst == NULL || src == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (dst == src) {
        return PMX_OK;
    }

    /* Reserve capacity for EVERY array before copying ANY of them.
     *
     * This is deliberately two passes. Growing-and-copying one array at a time
     * meant a realloc failure partway through left `dst` holding some arrays
     * from the new generation and some from the old. The engine publishes this
     * copy as the snapshot that backend threads resolve verdicts against, so a
     * half-updated copy would enforce a mixture of two profiles — e.g. a rule
     * the user just disabled still proxying, or pointing at a proxy that no
     * longer exists. Reserving first makes the operation all-or-nothing: on
     * failure `dst` is untouched and the previous consistent snapshot stands. */
#define PMX_RESERVE_ARRAY(field, count_field, cap_field, type)                  \
    do {                                                                        \
        if (src->count_field > dst->cap_field) {                                \
            size_t nc = dst->cap_field ? dst->cap_field : 8u;                   \
            while (nc < src->count_field) {                                     \
                nc *= 2u;                                                       \
            }                                                                   \
            type *np = (type *)realloc(dst->field, nc * sizeof(type));          \
            if (np == NULL) {                                                   \
                return PMX_ERR_NO_MEMORY;                                       \
            }                                                                   \
            dst->field = np;                                                    \
            dst->cap_field = nc;                                                \
        }                                                                       \
    } while (0)

#define PMX_ASSIGN_ARRAY(field, count_field, type)                              \
    do {                                                                        \
        if (src->count_field > 0) {                                             \
            memcpy(dst->field, src->field, src->count_field * sizeof(type));    \
        }                                                                       \
        dst->count_field = src->count_field;                                    \
    } while (0)

    PMX_RESERVE_ARRAY(proxies, proxy_count, proxy_cap, pmx_proxy);
    PMX_RESERVE_ARRAY(rules, rule_count, rule_cap, pmx_rule);
    PMX_RESERVE_ARRAY(chains, chain_count, chain_cap, pmx_chain);
    PMX_RESERVE_ARRAY(vpns, vpn_count, vpn_cap, pmx_vpn);

    PMX_ASSIGN_ARRAY(proxies, proxy_count, pmx_proxy);
    PMX_ASSIGN_ARRAY(rules, rule_count, pmx_rule);
    PMX_ASSIGN_ARRAY(chains, chain_count, pmx_chain);
    PMX_ASSIGN_ARRAY(vpns, vpn_count, pmx_vpn);
#undef PMX_RESERVE_ARRAY
#undef PMX_ASSIGN_ARRAY

    pmx_strlcpy(dst->label, src->label, sizeof(dst->label));
    pmx_strlcpy(dst->path, src->path, sizeof(dst->path));
    dst->default_rule = src->default_rule;
    dst->lockdown = src->lockdown;
    dst->settings = src->settings;
    dst->next_id = src->next_id;
    return PMX_OK;
}

pmx_id pmx_profile_next_id(pmx_profile *pf) {
    if (pf == NULL) {
        return PMX_ID_NONE;
    }
    if (pf->next_id == PMX_ID_NONE) {
        pf->next_id = 1;
    }
    return pf->next_id++;
}

/* ------------------------------------------------------------------ proxies */

static pmx_proxy *append_proxy(pmx_profile *pf) {
    PMX_GROW(&pf->proxies, &pf->proxy_cap, pf->proxy_count, pmx_proxy);
    pmx_proxy *p = &pf->proxies[pf->proxy_count++];
    memset(p, 0, sizeof(*p));
    return p;
}

pmx_proxy *pmx_profile_add_proxy(pmx_profile *pf) {
    if (pf == NULL) {
        return NULL;
    }
    pmx_proxy *p = append_proxy(pf);
    if (p == NULL) {
        return NULL;
    }
    pmx_proxy_init(p);
    p->id = pmx_profile_next_id(pf);
    return p;
}

pmx_proxy *pmx_profile_find_proxy(pmx_profile *pf, pmx_id id) {
    if (pf == NULL || id == PMX_ID_NONE) {
        return NULL;
    }
    for (size_t i = 0; i < pf->proxy_count; i++) {
        if (pf->proxies[i].id == id) {
            return &pf->proxies[i];
        }
    }
    return NULL;
}

const pmx_proxy *pmx_profile_find_proxy_c(const pmx_profile *pf, pmx_id id) {
    return pmx_profile_find_proxy((pmx_profile *)pf, id);
}

pmx_status pmx_profile_remove_proxy(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t idx = pf->proxy_count;
    for (size_t i = 0; i < pf->proxy_count; i++) {
        if (pf->proxies[i].id == id) {
            idx = i;
            break;
        }
    }
    if (idx == pf->proxy_count) {
        return PMX_ERR_NOT_FOUND;
    }
    for (size_t i = idx; i + 1 < pf->proxy_count; i++) {
        pf->proxies[i] = pf->proxies[i + 1];
    }
    pf->proxy_count--;

    /* Fix up chains that referenced it — and the right fix depends on what the
     * chain's hops MEAN.
     *
     * SEQUENTIAL: the hops are a path, so their number and order are the
     * protection the user asked for. Compacting the deleted hop out would
     * silently turn a 3-hop chain into a 2-hop one and quietly route traffic
     * through less protection than requested — the exact under-proxying this
     * project refuses elsewhere. Leave the reference dangling instead: the
     * engine's resolver is already all-or-nothing on an unresolvable hop, so the
     * flow fails closed, and the editor already renders it as "(missing proxy)"
     * with a Remove button, so it is visible and fixable rather than silent.
     * This mirrors how a rule pointing at the deleted proxy is handled below.
     *
     * REDUNDANCY: the hops are an unordered set of alternatives, so dropping one
     * genuinely leaves a smaller-but-correct set. Compact it. */
    for (size_t c = 0; c < pf->chain_count; c++) {
        pmx_chain *ch = &pf->chains[c];
        if (ch->mode == PMX_CHAIN_REDUNDANCY) {
            size_t w = 0;
            for (size_t h = 0; h < ch->hop_count; h++) {
                if (ch->hops[h] != id) {
                    ch->hops[w++] = ch->hops[h];
                }
            }
            ch->hop_count = w;
        } else {
            for (size_t h = 0; h < ch->hop_count; h++) {
                if (ch->hops[h] == id) {
                    ch->hops[h] = PMX_ID_NONE;
                }
            }
        }
    }
    /* Flag rules that pointed at it as missing (validate() will surface it). */
    for (size_t r = 0; r < pf->rule_count; r++) {
        if (pf->rules[r].target_kind == PMX_TARGET_PROXY &&
            pf->rules[r].target_id == id) {
            pf->rules[r].target_id = PMX_ID_NONE;
        }
    }
    return PMX_OK;
}

/* -------------------------------------------------------------------- rules */

static pmx_rule *append_rule(pmx_profile *pf) {
    PMX_GROW(&pf->rules, &pf->rule_cap, pf->rule_count, pmx_rule);
    pmx_rule *r = &pf->rules[pf->rule_count++];
    memset(r, 0, sizeof(*r));
    return r;
}

pmx_rule *pmx_profile_add_rule(pmx_profile *pf) {
    if (pf == NULL) {
        return NULL;
    }
    pmx_rule *r = append_rule(pf);
    if (r == NULL) {
        return NULL;
    }
    pmx_rule_init(r);
    r->id = pmx_profile_next_id(pf);
    return r;
}

pmx_rule *pmx_profile_find_rule(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].id == id) {
            return &pf->rules[i];
        }
    }
    return NULL;
}

pmx_status pmx_profile_remove_rule(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].id == id) {
            for (size_t j = i; j + 1 < pf->rule_count; j++) {
                pf->rules[j] = pf->rules[j + 1];
            }
            pf->rule_count--;
            return PMX_OK;
        }
    }
    return PMX_ERR_NOT_FOUND;
}

pmx_status pmx_profile_move_rule(pmx_profile *pf, size_t from, size_t to) {
    if (pf == NULL || from >= pf->rule_count || to >= pf->rule_count) {
        return PMX_ERR_INVALID_ARG;
    }
    if (from == to) {
        return PMX_OK;
    }
    pmx_rule moved = pf->rules[from];
    if (from < to) {
        for (size_t i = from; i < to; i++) {
            pf->rules[i] = pf->rules[i + 1];
        }
    } else {
        for (size_t i = from; i > to; i--) {
            pf->rules[i] = pf->rules[i - 1];
        }
    }
    pf->rules[to] = moved;
    return PMX_OK;
}

/* ------------------------------------------------------------------- chains */

static pmx_chain *append_chain(pmx_profile *pf) {
    PMX_GROW(&pf->chains, &pf->chain_cap, pf->chain_count, pmx_chain);
    pmx_chain *c = &pf->chains[pf->chain_count++];
    memset(c, 0, sizeof(*c));
    return c;
}

pmx_chain *pmx_profile_add_chain(pmx_profile *pf) {
    if (pf == NULL) {
        return NULL;
    }
    pmx_chain *c = append_chain(pf);
    if (c == NULL) {
        return NULL;
    }
    pmx_chain_init(c);
    c->id = pmx_profile_next_id(pf);
    return c;
}

pmx_chain *pmx_profile_find_chain(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < pf->chain_count; i++) {
        if (pf->chains[i].id == id) {
            return &pf->chains[i];
        }
    }
    return NULL;
}

const pmx_chain *pmx_profile_find_chain_c(const pmx_profile *pf, pmx_id id) {
    return pmx_profile_find_chain((pmx_profile *)pf, id);
}

pmx_status pmx_profile_remove_chain(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < pf->chain_count; i++) {
        if (pf->chains[i].id == id) {
            for (size_t j = i; j + 1 < pf->chain_count; j++) {
                pf->chains[j] = pf->chains[j + 1];
            }
            pf->chain_count--;
            for (size_t r = 0; r < pf->rule_count; r++) {
                if (pf->rules[r].target_kind == PMX_TARGET_CHAIN &&
                    pf->rules[r].target_id == id) {
                    pf->rules[r].target_id = PMX_ID_NONE;
                }
            }
            return PMX_OK;
        }
    }
    return PMX_ERR_NOT_FOUND;
}

/* --------------------------------------------------------------------- VPNs */

static pmx_vpn *append_vpn(pmx_profile *pf) {
    PMX_GROW(&pf->vpns, &pf->vpn_cap, pf->vpn_count, pmx_vpn);
    pmx_vpn *v = &pf->vpns[pf->vpn_count++];
    memset(v, 0, sizeof(*v));
    return v;
}

pmx_vpn *pmx_profile_add_vpn(pmx_profile *pf) {
    if (pf == NULL) {
        return NULL;
    }
    pmx_vpn *v = append_vpn(pf);
    if (v == NULL) {
        return NULL;
    }
    pmx_vpn_init(v);
    v->id = pmx_profile_next_id(pf);
    return v;
}

pmx_vpn *pmx_profile_find_vpn(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < pf->vpn_count; i++) {
        if (pf->vpns[i].id == id) {
            return &pf->vpns[i];
        }
    }
    return NULL;
}

pmx_status pmx_profile_remove_vpn(pmx_profile *pf, pmx_id id) {
    if (pf == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < pf->vpn_count; i++) {
        if (pf->vpns[i].id == id) {
            for (size_t j = i; j + 1 < pf->vpn_count; j++) {
                pf->vpns[j] = pf->vpns[j + 1];
            }
            pf->vpn_count--;
            return PMX_OK;
        }
    }
    return PMX_ERR_NOT_FOUND;
}

pmx_status pmx_profile_import_vpn(pmx_profile *pf, const char *path,
                                  pmx_vpn **out) {
    if (pf == NULL || path == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_vpn parsed;
    pmx_status st = pmx_vpn_load_file(path, &parsed);
    if (st != PMX_OK) {
        return st;
    }
    pmx_vpn *v = append_vpn(pf);
    if (v == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    *v = parsed;
    v->id = pmx_profile_next_id(pf);
    if (out != NULL) {
        *out = v;
    }
    return PMX_OK;
}

/* ------------------------------------------------------------------ helpers */

void pmx_profile_target_label(const pmx_profile *pf, pmx_target_kind kind,
                              pmx_id id, char *buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) {
        return;
    }
    if (kind == PMX_TARGET_NONE || id == PMX_ID_NONE) {
        pmx_strlcpy(buf, "\xE2\x80\x94", buf_size); /* em dash */
        return;
    }
    if (kind == PMX_TARGET_PROXY) {
        const pmx_proxy *p = pmx_profile_find_proxy_c(pf, id);
        pmx_strlcpy(buf, p != NULL ? p->label : "(missing)", buf_size);
    } else if (kind == PMX_TARGET_CHAIN) {
        const pmx_chain *c = pmx_profile_find_chain_c(pf, id);
        pmx_strlcpy(buf, c != NULL ? c->label : "(missing)", buf_size);
    } else {
        pmx_strlcpy(buf, "?", buf_size);
    }
}

pmx_status pmx_profile_validate(const pmx_profile *pf, char *msg,
                                size_t msg_size) {
#define VFAIL(text)                                                             \
    do {                                                                        \
        if (msg != NULL)                                                        \
            pmx_strlcpy(msg, (text), msg_size);                                 \
        return PMX_ERR_PARSE;                                                   \
    } while (0)

    if (pf == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < pf->rule_count; i++) {
        const pmx_rule *r = &pf->rules[i];
        if (pmx_port_spec_validate(r->port_spec) != PMX_OK) {
            VFAIL("a rule has an invalid port spec");
        }
        if (r->action == PMX_ACTION_PROXY) {
            if (r->target_kind == PMX_TARGET_PROXY &&
                pmx_profile_find_proxy_c(pf, r->target_id) == NULL) {
                VFAIL("a rule points at a missing proxy");
            }
            if (r->target_kind == PMX_TARGET_CHAIN &&
                pmx_profile_find_chain_c(pf, r->target_id) == NULL) {
                VFAIL("a rule points at a missing chain");
            }
            if (r->target_kind == PMX_TARGET_NONE) {
                VFAIL("a proxy rule has no target selected");
            }
        }
    }
    for (size_t c = 0; c < pf->chain_count; c++) {
        const pmx_chain *ch = &pf->chains[c];
        for (size_t h = 0; h < ch->hop_count; h++) {
            if (pmx_profile_find_proxy_c(pf, ch->hops[h]) == NULL) {
                VFAIL("a chain references a missing proxy");
            }
        }
    }
    if (msg != NULL && msg_size > 0) {
        msg[0] = '\0';
    }
    return PMX_OK;
#undef VFAIL
}

/* ------------------------------------------------------------ seed defaults */

void pmx_profile_seed_defaults(pmx_profile *pf) {
    if (pf == NULL) {
        return;
    }
    pmx_profile_init(pf);
    pmx_strlcpy(pf->label, "Default profile", sizeof(pf->label));

    pmx_proxy *tor = pmx_profile_add_proxy(pf);
    if (tor != NULL) {
        pmx_strlcpy(tor->label, "Local Tor (SOCKS5)", sizeof(tor->label));
        tor->type = PMX_PROXY_SOCKS5;
        pmx_strlcpy(tor->host, "127.0.0.1", sizeof(tor->host));
        tor->port = 9050;
        tor->enabled = true;
    }
    pmx_proxy *http = pmx_profile_add_proxy(pf);
    if (http != NULL) {
        pmx_strlcpy(http->label, "Example HTTP proxy", sizeof(http->label));
        http->type = PMX_PROXY_HTTP;
        pmx_strlcpy(http->host, "127.0.0.1", sizeof(http->host));
        http->port = 8080;
        http->enabled = false;
    }

    /* Keep local/LAN traffic direct. */
    pmx_rule *local = pmx_profile_add_rule(pf);
    if (local != NULL) {
        pmx_strlcpy(local->name, "Local & LAN direct", sizeof(local->name));
        /* Numeric patterns only, deliberately. A real redirection backend sees
         * the connect after the app resolved the name, so dst_host is an IP
         * literal — "localhost" and "*.local" would never match and would just
         * be decoration. 127.* already covers loopback. */
        pmx_strlcpy(local->host_pattern,
                    "127.*;10.*;192.168.*;172.16.*;169.254.*",
                    sizeof(local->host_pattern));
        local->action = PMX_ACTION_DIRECT;
        local->target_kind = PMX_TARGET_NONE;
    }

    /* Route common browsers through the Tor SOCKS proxy. */
    pmx_rule *browsers = pmx_profile_add_rule(pf);
    if (browsers != NULL) {
        pmx_strlcpy(browsers->name, "Browsers via Tor", sizeof(browsers->name));
        pmx_strlcpy(browsers->app_pattern,
                    "chrome.exe;firefox.exe;msedge.exe;Google Chrome;firefox",
                    sizeof(browsers->app_pattern));
        browsers->action = PMX_ACTION_PROXY;
        browsers->target_kind = PMX_TARGET_PROXY;
        browsers->target_id = (tor != NULL) ? tor->id : PMX_ID_NONE;
    }

    /* The catch-all default: everything else goes direct. */
    pmx_strlcpy(pf->default_rule.name, "Default", sizeof(pf->default_rule.name));
    pf->default_rule.action = PMX_ACTION_DIRECT;
    pf->default_rule.target_kind = PMX_TARGET_NONE;
}

/* --------------------------------------------------------------- JSON I/O */

static void rule_to_json(cJSON *o, const pmx_rule *r) {
    cJSON_AddNumberToObject(o, "id", (double)r->id);
    cJSON_AddStringToObject(o, "name", r->name);
    cJSON_AddBoolToObject(o, "enabled", r->enabled);
    pmx_json_add_str_if(o, "app", r->app_pattern);
    pmx_json_add_str_if(o, "host", r->host_pattern);
    pmx_json_add_str_if(o, "ports", r->port_spec);
    cJSON_AddNumberToObject(o, "action", (double)r->action);
    cJSON_AddNumberToObject(o, "target_kind", (double)r->target_kind);
    cJSON_AddNumberToObject(o, "target_id", (double)r->target_id);
}

/* Clamp a persisted integer into a sane range.
 *
 * Profile JSON is not trusted input: it can be hand-edited, shared between
 * users, or written by another build. Timeouts in particular are cast to DWORD
 * deep in the checker (IcmpSendEcho) and to a timeval in select(), so a negative
 * or absurd value becomes a multi-week wait on a worker thread that nothing can
 * interrupt — which then hangs shutdown, because destroy joins that thread. */
static int clamp_int(int v, int lo, int hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

static void rule_from_json(const cJSON *o, pmx_rule *r) {
    pmx_rule_init(r);
    r->id = (pmx_id)pmx_json_int(o, "id", 0);
    pmx_json_str_into(o, "name", r->name, sizeof(r->name), "Rule");
    r->enabled = pmx_json_bool(o, "enabled", true);
    pmx_json_str_into(o, "app", r->app_pattern, sizeof(r->app_pattern), "");
    pmx_json_str_into(o, "host", r->host_pattern, sizeof(r->host_pattern), "");
    pmx_json_str_into(o, "ports", r->port_spec, sizeof(r->port_spec), "");
    r->action = (pmx_action)pmx_json_int(o, "action", PMX_ACTION_DIRECT);
    r->target_kind =
        (pmx_target_kind)pmx_json_int(o, "target_kind", PMX_TARGET_NONE);
    r->target_id = (pmx_id)pmx_json_int(o, "target_id", 0);
}

pmx_status pmx_profile_to_json(const pmx_profile *pf, char **out) {
    if (pf == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = NULL;
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    cJSON_AddStringToObject(root, "format", PMX_PROFILE_FORMAT);
    cJSON_AddNumberToObject(root, "version", PMX_PROFILE_VERSION);
    cJSON_AddStringToObject(root, "label", pf->label);
    cJSON_AddNumberToObject(root, "next_id", (double)pf->next_id);

    /* settings */
    cJSON *st = cJSON_AddObjectToObject(root, "settings");
    cJSON_AddBoolToObject(st, "dns_through_proxy", pf->settings.dns_through_proxy);
    cJSON_AddBoolToObject(st, "demo_traffic", pf->settings.demo_traffic);
    cJSON_AddNumberToObject(st, "demo_interval_ms", pf->settings.demo_interval_ms);
    cJSON *ck = cJSON_AddObjectToObject(st, "check");
    cJSON_AddStringToObject(ck, "probe_host", pf->settings.check.probe_host);
    cJSON_AddNumberToObject(ck, "probe_port", pf->settings.check.probe_port);
    cJSON_AddNumberToObject(ck, "timeout_ms", pf->settings.check.timeout_ms);
    cJSON_AddBoolToObject(ck, "measure_egress_ip",
                          pf->settings.check.measure_egress_ip);
    cJSON_AddBoolToObject(ck, "measure_ping", pf->settings.check.measure_ping);
    cJSON_AddStringToObject(ck, "egress_service", pf->settings.check.egress_service);
    cJSON_AddStringToObject(ck, "egress_path", pf->settings.check.egress_path);
    pmx_json_add_str_if(st, "wireguard_path", pf->settings.wireguard_path);
    pmx_json_add_str_if(st, "openvpn_path", pf->settings.openvpn_path);

    /* lockdown */
    cJSON *ld = cJSON_AddObjectToObject(root, "lockdown");
    cJSON_AddNumberToObject(ld, "mode", (double)pf->lockdown.mode);
    cJSON_AddBoolToObject(ld, "block_until_verified",
                          pf->lockdown.block_until_verified);
    cJSON_AddBoolToObject(ld, "block_dns_leak", pf->lockdown.block_dns_leak);
    cJSON_AddBoolToObject(ld, "block_ipv6", pf->lockdown.block_ipv6);
    cJSON_AddNumberToObject(ld, "health_interval_ms",
                            pf->lockdown.health_interval_ms);
    cJSON_AddNumberToObject(ld, "failures_before_trip",
                            pf->lockdown.failures_before_trip);
    cJSON_AddNumberToObject(ld, "successes_before_restore",
                            pf->lockdown.successes_before_restore);

    /* proxies */
    cJSON *parr = cJSON_AddArrayToObject(root, "proxies");
    for (size_t i = 0; i < pf->proxy_count; i++) {
        const pmx_proxy *p = &pf->proxies[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", (double)p->id);
        cJSON_AddStringToObject(o, "label", p->label);
        cJSON_AddStringToObject(o, "type", pmx_proxy_type_short(p->type));
        cJSON_AddStringToObject(o, "host", p->host);
        cJSON_AddNumberToObject(o, "port", p->port);
        cJSON_AddBoolToObject(o, "use_auth", p->use_auth);
        pmx_json_add_str_if(o, "username", p->username);
        /* The password lives in this in-memory JSON, but the file written by
         * pmx_profile_save is sealed at rest (DPAPI on Windows) so it never
         * hits disk in cleartext. See pmx_protect.h / docs/PRIVACY-SECURITY.md.
         * On platforms with no provider the file is still plaintext — the save
         * path logs a loud warning in that case. */
        pmx_json_add_str_if(o, "password", p->password);
        cJSON_AddBoolToObject(o, "enabled", p->enabled);
        cJSON_AddItemToArray(parr, o);
    }

    /* chains */
    cJSON *carr = cJSON_AddArrayToObject(root, "chains");
    for (size_t i = 0; i < pf->chain_count; i++) {
        const pmx_chain *c = &pf->chains[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", (double)c->id);
        cJSON_AddStringToObject(o, "label", c->label);
        cJSON_AddNumberToObject(o, "mode", (double)c->mode);
        cJSON_AddBoolToObject(o, "enabled", c->enabled);
        cJSON *hops = cJSON_AddArrayToObject(o, "hops");
        for (size_t h = 0; h < c->hop_count; h++) {
            cJSON_AddItemToArray(hops, cJSON_CreateNumber((double)c->hops[h]));
        }
        cJSON_AddItemToArray(carr, o);
    }

    /* vpns — non-secret metadata only. The tunnel's keys stay in the original
     * config file on disk; see the secrets policy in pmx_vpn.h. */
    cJSON *varr = cJSON_AddArrayToObject(root, "vpns");
    for (size_t i = 0; i < pf->vpn_count; i++) {
        const pmx_vpn *v = &pf->vpns[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", (double)v->id);
        cJSON_AddStringToObject(o, "label", v->label);
        cJSON_AddNumberToObject(o, "kind", (double)v->kind);
        cJSON_AddBoolToObject(o, "enabled", v->enabled);
        pmx_json_add_str_if(o, "config_path", v->config_path);
        pmx_json_add_str_if(o, "dns", v->dns);
        cJSON_AddNumberToObject(o, "mtu", v->mtu);
        pmx_json_add_str_if(o, "address", v->address);
        pmx_json_add_str_if(o, "allowed_ips", v->allowed_ips);
        pmx_json_add_str_if(o, "peer_public_key", v->peer_public_key);
        cJSON_AddNumberToObject(o, "keepalive", v->persistent_keepalive);
        pmx_json_add_str_if(o, "cipher", v->cipher);
        pmx_json_add_str_if(o, "auth", v->auth_digest);
        pmx_json_add_str_if(o, "dev", v->dev);
        cJSON_AddBoolToObject(o, "has_private_key", v->has_private_key);
        cJSON_AddBoolToObject(o, "has_preshared_key", v->has_preshared_key);
        cJSON_AddBoolToObject(o, "has_inline_secrets", v->has_inline_secrets);
        cJSON_AddBoolToObject(o, "requires_user_pass", v->requires_user_pass);
        cJSON_AddBoolToObject(o, "full_tunnel", v->full_tunnel);
        cJSON *eps = cJSON_AddArrayToObject(o, "endpoints");
        for (size_t j = 0; j < v->endpoint_count; j++) {
            cJSON *e = cJSON_CreateObject();
            cJSON_AddStringToObject(e, "host", v->endpoints[j].host);
            cJSON_AddNumberToObject(e, "port", v->endpoints[j].port);
            cJSON_AddBoolToObject(e, "udp", v->endpoints[j].udp);
            cJSON_AddItemToArray(eps, e);
        }
        cJSON_AddItemToArray(varr, o);
    }

    /* rules + default rule */
    cJSON *rarr = cJSON_AddArrayToObject(root, "rules");
    for (size_t i = 0; i < pf->rule_count; i++) {
        cJSON *o = cJSON_CreateObject();
        rule_to_json(o, &pf->rules[i]);
        cJSON_AddItemToArray(rarr, o);
    }
    cJSON *dr = cJSON_AddObjectToObject(root, "default_rule");
    rule_to_json(dr, &pf->default_rule);

    char *text = cJSON_Print(root);
    cJSON_Delete(root);
    if (text == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    *out = text;
    return PMX_OK;
}

pmx_status pmx_profile_from_json(pmx_profile *pf, const char *json) {
    if (pf == NULL || json == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        return PMX_ERR_PARSE;
    }
    const char *fmt = pmx_json_str(root, "format", "");
    if (strcmp(fmt, PMX_PROFILE_FORMAT) != 0) {
        cJSON_Delete(root);
        return PMX_ERR_PARSE;
    }

    pmx_profile_init(pf);
    pmx_json_str_into(root, "label", pf->label, sizeof(pf->label), "Profile");
    pf->next_id = (pmx_id)pmx_json_int(root, "next_id", 1);

    const cJSON *st = cJSON_GetObjectItemCaseSensitive(root, "settings");
    if (st != NULL) {
        pf->settings.dns_through_proxy = pmx_json_bool(st, "dns_through_proxy", true);
        pf->settings.demo_traffic = pmx_json_bool(st, "demo_traffic", true);
        pf->settings.demo_interval_ms = pmx_json_int(st, "demo_interval_ms", 1500);
        pmx_json_str_into(st, "wireguard_path", pf->settings.wireguard_path,
                          sizeof(pf->settings.wireguard_path), "");
        pmx_json_str_into(st, "openvpn_path", pf->settings.openvpn_path,
                          sizeof(pf->settings.openvpn_path), "");
        const cJSON *ck = cJSON_GetObjectItemCaseSensitive(st, "check");
        if (ck != NULL) {
            pmx_json_str_into(ck, "probe_host", pf->settings.check.probe_host,
                              sizeof(pf->settings.check.probe_host), "example.com");
            pf->settings.check.probe_port =
                (pmx_port)pmx_json_int(ck, "probe_port", 443);
            pf->settings.check.timeout_ms =
                clamp_int(pmx_json_int(ck, "timeout_ms", 5000), 500, 30000);
            pf->settings.check.measure_egress_ip =
                pmx_json_bool(ck, "measure_egress_ip", false);
            pf->settings.check.measure_ping = pmx_json_bool(ck, "measure_ping", true);
            pmx_json_str_into(ck, "egress_service",
                              pf->settings.check.egress_service,
                              sizeof(pf->settings.check.egress_service), "");
            pmx_json_str_into(ck, "egress_path", pf->settings.check.egress_path,
                              sizeof(pf->settings.check.egress_path), "/");
        }
    }

    const cJSON *ld = cJSON_GetObjectItemCaseSensitive(root, "lockdown");
    if (ld != NULL) {
        pf->lockdown.mode =
            (pmx_lockdown_mode)pmx_json_int(ld, "mode", PMX_LOCKDOWN_FAIL_CLOSED);
        pf->lockdown.block_until_verified =
            pmx_json_bool(ld, "block_until_verified", true);
        pf->lockdown.block_dns_leak = pmx_json_bool(ld, "block_dns_leak", true);
        pf->lockdown.block_ipv6 = pmx_json_bool(ld, "block_ipv6", true);
        pf->lockdown.health_interval_ms =
            clamp_int(pmx_json_int(ld, "health_interval_ms", 4000), 500, 600000);
        pf->lockdown.failures_before_trip =
            clamp_int(pmx_json_int(ld, "failures_before_trip", 2), 1, 100);
        pf->lockdown.successes_before_restore =
            clamp_int(pmx_json_int(ld, "successes_before_restore", 2), 1, 100);
    }

    const cJSON *parr = cJSON_GetObjectItemCaseSensitive(root, "proxies");
    if (cJSON_IsArray(parr)) {
        const cJSON *o = NULL;
        cJSON_ArrayForEach(o, parr) {
            pmx_proxy *p = append_proxy(pf);
            if (p == NULL) {
                break;
            }
            pmx_proxy_init(p);
            p->id = (pmx_id)pmx_json_int(o, "id", 0);
            pmx_json_str_into(o, "label", p->label, sizeof(p->label), "Proxy");
            pmx_proxy_type type = PMX_PROXY_SOCKS5;
            pmx_proxy_type_from_str(pmx_json_str(o, "type", "socks5"), &type);
            p->type = type;
            pmx_json_str_into(o, "host", p->host, sizeof(p->host), "");
            p->port = (pmx_port)pmx_json_int(o, "port", 1080);
            p->use_auth = pmx_json_bool(o, "use_auth", false);
            pmx_json_str_into(o, "username", p->username, sizeof(p->username), "");
            pmx_json_str_into(o, "password", p->password, sizeof(p->password), "");
            p->enabled = pmx_json_bool(o, "enabled", true);
        }
    }

    const cJSON *carr = cJSON_GetObjectItemCaseSensitive(root, "chains");
    if (cJSON_IsArray(carr)) {
        const cJSON *o = NULL;
        cJSON_ArrayForEach(o, carr) {
            pmx_chain *c = append_chain(pf);
            if (c == NULL) {
                break;
            }
            pmx_chain_init(c);
            c->id = (pmx_id)pmx_json_int(o, "id", 0);
            pmx_json_str_into(o, "label", c->label, sizeof(c->label), "Chain");
            c->mode = (pmx_chain_mode)pmx_json_int(o, "mode", PMX_CHAIN_SEQUENTIAL);
            c->enabled = pmx_json_bool(o, "enabled", true);
            const cJSON *hops = cJSON_GetObjectItemCaseSensitive(o, "hops");
            if (cJSON_IsArray(hops)) {
                const cJSON *hv = NULL;
                cJSON_ArrayForEach(hv, hops) {
                    if (cJSON_IsNumber(hv) && c->hop_count < PMX_MAX_CHAIN_HOPS) {
                        c->hops[c->hop_count++] = (pmx_id)hv->valuedouble;
                    }
                }
            }
        }
    }

    const cJSON *varr = cJSON_GetObjectItemCaseSensitive(root, "vpns");
    if (cJSON_IsArray(varr)) {
        const cJSON *o = NULL;
        cJSON_ArrayForEach(o, varr) {
            pmx_vpn *v = append_vpn(pf);
            if (v == NULL) {
                break;
            }
            pmx_vpn_init(v);
            v->id = (pmx_id)pmx_json_int(o, "id", 0);
            pmx_json_str_into(o, "label", v->label, sizeof(v->label), "VPN");
            v->kind = (pmx_vpn_kind)pmx_json_int(o, "kind", PMX_VPN_WIREGUARD);
            v->enabled = pmx_json_bool(o, "enabled", true);
            pmx_json_str_into(o, "config_path", v->config_path,
                              sizeof(v->config_path), "");
            pmx_json_str_into(o, "dns", v->dns, sizeof(v->dns), "");
            v->mtu = pmx_json_int(o, "mtu", 0);
            pmx_json_str_into(o, "address", v->address, sizeof(v->address), "");
            pmx_json_str_into(o, "allowed_ips", v->allowed_ips,
                              sizeof(v->allowed_ips), "");
            pmx_json_str_into(o, "peer_public_key", v->peer_public_key,
                              sizeof(v->peer_public_key), "");
            v->persistent_keepalive = pmx_json_int(o, "keepalive", 0);
            pmx_json_str_into(o, "cipher", v->cipher, sizeof(v->cipher), "");
            pmx_json_str_into(o, "auth", v->auth_digest, sizeof(v->auth_digest), "");
            pmx_json_str_into(o, "dev", v->dev, sizeof(v->dev), "");
            v->has_private_key = pmx_json_bool(o, "has_private_key", false);
            v->has_preshared_key = pmx_json_bool(o, "has_preshared_key", false);
            v->has_inline_secrets = pmx_json_bool(o, "has_inline_secrets", false);
            v->requires_user_pass = pmx_json_bool(o, "requires_user_pass", false);
            v->full_tunnel = pmx_json_bool(o, "full_tunnel", false);
            const cJSON *eps = cJSON_GetObjectItemCaseSensitive(o, "endpoints");
            if (cJSON_IsArray(eps)) {
                const cJSON *e = NULL;
                cJSON_ArrayForEach(e, eps) {
                    if (v->endpoint_count >= PMX_MAX_VPN_ENDPOINTS) {
                        break;
                    }
                    pmx_vpn_endpoint *ep = &v->endpoints[v->endpoint_count++];
                    memset(ep, 0, sizeof(*ep));
                    pmx_json_str_into(e, "host", ep->host, sizeof(ep->host), "");
                    ep->port = (pmx_port)pmx_json_int(e, "port", 0);
                    ep->udp = pmx_json_bool(e, "udp", true);
                }
            }
        }
    }

    const cJSON *rarr = cJSON_GetObjectItemCaseSensitive(root, "rules");
    if (cJSON_IsArray(rarr)) {
        const cJSON *o = NULL;
        cJSON_ArrayForEach(o, rarr) {
            pmx_rule *r = append_rule(pf);
            if (r == NULL) {
                break;
            }
            rule_from_json(o, r);
        }
    }

    const cJSON *dr = cJSON_GetObjectItemCaseSensitive(root, "default_rule");
    if (dr != NULL) {
        rule_from_json(dr, &pf->default_rule);
    }

    /* Make sure next_id can never collide with a stored id. */
    for (size_t i = 0; i < pf->proxy_count; i++) {
        if (pf->proxies[i].id >= pf->next_id) pf->next_id = pf->proxies[i].id + 1;
    }
    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].id >= pf->next_id) pf->next_id = pf->rules[i].id + 1;
    }
    for (size_t i = 0; i < pf->chain_count; i++) {
        if (pf->chains[i].id >= pf->next_id) pf->next_id = pf->chains[i].id + 1;
    }

    cJSON_Delete(root);
    return PMX_OK;
}

void pmx_profile_string_free(char *s) { free(s); }

/* ------------------------------------------------------------ file I/O */

static pmx_status read_whole_file(const char *path, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return PMX_ERR_IO;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return PMX_ERR_IO;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return PMX_ERR_NO_MEMORY;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    if (out_len != NULL) {
        *out_len = rd;
    }
    return PMX_OK;
}

/* Write `len` bytes atomically: temp file + flush + rename over the target.
 * (Windows rename() fails if the target exists, hence the remove().) */
static pmx_status write_file_atomic(const char *path, const void *bytes,
                                    size_t len) {
    char tmp[PMX_MAX_PATH + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (f == NULL) {
        return PMX_ERR_IO;
    }
    size_t wr = (len > 0) ? fwrite(bytes, 1, len, f) : 0;
    fflush(f);
    fclose(f);
    if (wr != len) {
        remove(tmp);
        return PMX_ERR_IO;
    }

    /* Replace atomically, WITHOUT deleting the target first.
     *
     * The old sequence was remove(path) then rename(tmp, path), which opens a
     * window where the user has no profile at all — and if the rename then
     * fails (on Windows a sharing violation from an AV scanner or the search
     * indexer briefly holding the temp file is a real occurrence) the temp was
     * removed too and BOTH files were gone. That became a live data-loss path
     * the moment pmx_profile_load started rewriting the file to migrate legacy
     * plaintext: merely opening the app could destroy the profile.
     *
     * MoveFileEx with MOVEFILE_REPLACE_EXISTING replaces in one step, so a
     * failure leaves the original untouched. POSIX rename() already has that
     * semantic. Either way, on failure we keep the temp for diagnosis rather
     * than deleting the only surviving copy of the new content. */
#if defined(_WIN32)
    if (!MoveFileExA(tmp, path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return PMX_ERR_IO;
    }
#else
    if (rename(tmp, path) != 0) {
        return PMX_ERR_IO;
    }
#endif
    return PMX_OK;
}

/* On-disk container for a sealed profile:
 *   [0..7]   magic "PMXSEAL\0"      (trailing NUL: never mistaken for text JSON)
 *   [8..11]  uint32 LE format version
 *   [12..15] uint32 LE sealed-payload length N
 *   [16..]   N bytes of sealed blob (from pmx_protect_seal)
 * A legacy plaintext profile is raw JSON and starts with '{' (or whitespace),
 * so the magic distinguishes the two unambiguously on load. */
static const unsigned char PMX_SEAL_MAGIC[8] = {'P', 'M', 'X', 'S',
                                                'E', 'A', 'L', 0};
#define PMX_SEAL_HEADER 16u
#define PMX_SEAL_VERSION 1u

static void put_u32le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static bool looks_sealed(const unsigned char *buf, size_t len) {
    return buf != NULL && len >= PMX_SEAL_HEADER &&
           memcmp(buf, PMX_SEAL_MAGIC, sizeof(PMX_SEAL_MAGIC)) == 0;
}

pmx_status pmx_profile_save(const pmx_profile *pf, const char *path) {
    if (pf == NULL || path == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    char *json = NULL;
    pmx_status st = pmx_profile_to_json(pf, &json);
    if (st != PMX_OK) {
        return st;
    }
    size_t json_len = strlen(json);

    if (pmx_protect_available()) {
        void *sealed = NULL;
        size_t sealed_len = 0;
        st = pmx_protect_seal(json, json_len, &sealed, &sealed_len);
        pmx_protect_wipe(json, json_len); /* scrub the cleartext copy */
        pmx_profile_string_free(json);
        if (st != PMX_OK) {
            PMX_LOGE("Sealing profile '%s' failed (%s); nothing written.",
                     pf->label, pmx_status_str(st));
            return st;
        }
        if (sealed_len > 0xFFFFFFFFu) {
            pmx_protect_free(sealed);
            return PMX_ERR_IO;
        }
        size_t total = PMX_SEAL_HEADER + sealed_len;
        unsigned char *container = (unsigned char *)malloc(total);
        if (container == NULL) {
            pmx_protect_free(sealed);
            return PMX_ERR_NO_MEMORY;
        }
        memcpy(container, PMX_SEAL_MAGIC, sizeof(PMX_SEAL_MAGIC));
        put_u32le(container + 8, PMX_SEAL_VERSION);
        put_u32le(container + 12, (uint32_t)sealed_len);
        memcpy(container + PMX_SEAL_HEADER, sealed, sealed_len);
        pmx_protect_free(sealed);

        st = write_file_atomic(path, container, total);
        free(container);
        if (st != PMX_OK) {
            return st;
        }
        PMX_LOGI("Saved profile '%s' to %s (sealed at rest)", pf->label, path);
        return PMX_OK;
    }

    /* No at-rest crypto provider on this platform: write plaintext, loudly. */
    st = write_file_atomic(path, json, json_len);
    pmx_protect_wipe(json, json_len);
    pmx_profile_string_free(json);
    if (st != PMX_OK) {
        return st;
    }
    PMX_LOGW("Saved profile '%s' to %s (PLAINTEXT — no at-rest encryption "
             "provider on this platform)",
             pf->label, path);
    return PMX_OK;
}

pmx_status pmx_profile_load(pmx_profile *pf, const char *path) {
    if (pf == NULL || path == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    char *buf = NULL;
    size_t len = 0;
    pmx_status st = read_whole_file(path, &buf, &len);
    if (st != PMX_OK) {
        return st;
    }

    if (looks_sealed((const unsigned char *)buf, len)) {
        uint32_t ver = get_u32le((const unsigned char *)buf + 8);
        uint32_t plen = get_u32le((const unsigned char *)buf + 12);
        /* looks_sealed() guaranteed len >= PMX_SEAL_HEADER, so the subtraction
         * is safe and avoids overflowing plen + PMX_SEAL_HEADER (which on a
         * 32-bit size_t could wrap and let an over-long payload past the check
         * into pmx_protect_unseal). */
        if (ver != PMX_SEAL_VERSION || plen > len - PMX_SEAL_HEADER) {
            free(buf);
            PMX_LOGE("Profile %s has an unrecognized or truncated sealed header.",
                     path);
            return PMX_ERR_PARSE;
        }
        if (!pmx_protect_available()) {
            free(buf);
            PMX_LOGE("Profile %s is sealed but this build has no at-rest crypto "
                     "provider to open it.",
                     path);
            return PMX_ERR_UNSUPPORTED;
        }
        void *plain = NULL;
        size_t plain_len = 0;
        st = pmx_protect_unseal(buf + PMX_SEAL_HEADER, plen, &plain, &plain_len);
        free(buf);
        if (st != PMX_OK) {
            PMX_LOGE("Profile %s could not be decrypted (%s) — it was likely "
                     "created by a different user or on another machine.",
                     path, pmx_status_str(st));
            return PMX_ERR_CRYPTO;
        }
        /* cJSON wants a NUL-terminated string; the sealed payload is not. */
        char *json = (char *)malloc(plain_len + 1);
        if (json == NULL) {
            pmx_protect_wipe(plain, plain_len);
            pmx_protect_free(plain);
            return PMX_ERR_NO_MEMORY;
        }
        memcpy(json, plain, plain_len);
        json[plain_len] = '\0';
        pmx_protect_wipe(plain, plain_len);
        pmx_protect_free(plain);

        st = pmx_profile_from_json(pf, json);
        pmx_protect_wipe(json, plain_len);
        free(json);
        if (st == PMX_OK) {
            pmx_strlcpy(pf->path, path, sizeof(pf->path));
            PMX_LOGI("Loaded profile '%s' from %s (sealed)", pf->label, path);
        }
        return st;
    }

    /* Legacy plaintext JSON. Parse it, then transparently re-seal it in place
     * so credentials stop sitting on disk in cleartext from now on. */
    st = pmx_profile_from_json(pf, buf);
    pmx_protect_wipe(buf, len);
    free(buf);
    if (st != PMX_OK) {
        return st;
    }
    pmx_strlcpy(pf->path, path, sizeof(pf->path));

    if (pmx_protect_available()) {
        pmx_status mst = pmx_profile_save(pf, path); /* now writes a sealed file */
        if (mst == PMX_OK) {
            PMX_LOGI("Migrated plaintext profile '%s' at %s to sealed at-rest "
                     "storage.",
                     pf->label, path);
        } else {
            PMX_LOGW("Loaded plaintext profile '%s' but could not migrate it to "
                     "sealed storage (%s); it remains plaintext for now.",
                     pf->label, pmx_status_str(mst));
        }
    } else {
        PMX_LOGI("Loaded profile '%s' from %s (plaintext)", pf->label, path);
    }
    return PMX_OK;
}
