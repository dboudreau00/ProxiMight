/*
 * pmx_profile.h — a profile: the full set of proxies, rules, chains, the
 * default rule, lockdown policy, and settings. This is what gets saved to a
 * ".pmxprofile" JSON file and what the GUI edits.
 *
 * Lists grow dynamically; the small scalar strings are fixed-capacity. Every
 * proxy/rule/chain gets a stable id from the profile's monotonic counter so
 * rules and chains can reference them across reorders and reloads.
 */
#ifndef PROXIMIGHT_PMX_PROFILE_H
#define PROXIMIGHT_PMX_PROFILE_H

#include "proximight/pmx_proxy.h"
#include "proximight/pmx_rule.h"
#include "proximight/pmx_chain.h"
#include "proximight/pmx_lockdown.h"
#include "proximight/pmx_checker.h"
#include "proximight/pmx_vpn.h"

PMX_BEGIN_DECLS

#define PMX_PROFILE_FORMAT "pmxprofile"
#define PMX_PROFILE_VERSION 1

typedef struct pmx_profile_settings {
    bool dns_through_proxy; /* resolve target names at the proxy, not locally */
    bool demo_traffic;      /* stub backend: generate synthetic flows          */
    int demo_interval_ms;
    pmx_check_opts check;   /* checker defaults for this profile               */

    /* Optional overrides for the vendor VPN clients. Empty = auto-detect from
     * the standard install locations. The binaries are never vendored. */
    char wireguard_path[PMX_MAX_PATH];
    char openvpn_path[PMX_MAX_PATH];
} pmx_profile_settings;

typedef struct pmx_profile {
    char label[PMX_MAX_LABEL];
    char path[PMX_MAX_PATH]; /* last saved/loaded path (runtime, not persisted) */

    pmx_proxy *proxies;
    size_t proxy_count, proxy_cap;
    pmx_rule *rules;
    size_t rule_count, rule_cap;
    pmx_chain *chains;
    size_t chain_count, chain_cap;
    /* Overarching tunnels. Proxy rules ride on top of whichever VPN is up. */
    pmx_vpn *vpns;
    size_t vpn_count, vpn_cap;

    pmx_rule default_rule;         /* used when nothing else matches */
    pmx_lockdown_policy lockdown;
    pmx_profile_settings settings;

    pmx_id next_id;
} pmx_profile;

void pmx_profile_init(pmx_profile *pf);
void pmx_profile_free(pmx_profile *pf);
void pmx_profile_clear(pmx_profile *pf); /* empties lists, keeps allocations */

/* Deep-copy `src` into `dst`. `dst` must already be initialized; its arrays are
 * reused and grown as needed (so repeated copies don't churn the allocator).
 * The engine uses this to publish a snapshot that other threads can resolve
 * against without locking the live profile. */
pmx_status pmx_profile_copy(pmx_profile *dst, const pmx_profile *src);

/* Populate a friendly starter profile (a couple of example proxies, a sensible
 * default rule, safe lockdown defaults) so the app is useful on first launch. */
void pmx_profile_seed_defaults(pmx_profile *pf);

pmx_id pmx_profile_next_id(pmx_profile *pf);

/* --- proxies ------------------------------------------------------------ */
pmx_proxy *pmx_profile_add_proxy(pmx_profile *pf);   /* appends, returns ptr */
pmx_proxy *pmx_profile_find_proxy(pmx_profile *pf, pmx_id id);
const pmx_proxy *pmx_profile_find_proxy_c(const pmx_profile *pf, pmx_id id);
pmx_status pmx_profile_remove_proxy(pmx_profile *pf, pmx_id id);

/* --- rules -------------------------------------------------------------- */
pmx_rule *pmx_profile_add_rule(pmx_profile *pf);
pmx_rule *pmx_profile_find_rule(pmx_profile *pf, pmx_id id);
pmx_status pmx_profile_remove_rule(pmx_profile *pf, pmx_id id);
pmx_status pmx_profile_move_rule(pmx_profile *pf, size_t from, size_t to);

/* --- chains ------------------------------------------------------------- */
pmx_chain *pmx_profile_add_chain(pmx_profile *pf);
pmx_chain *pmx_profile_find_chain(pmx_profile *pf, pmx_id id);
const pmx_chain *pmx_profile_find_chain_c(const pmx_profile *pf, pmx_id id);
pmx_status pmx_profile_remove_chain(pmx_profile *pf, pmx_id id);

/* --- VPNs --------------------------------------------------------------- */
pmx_vpn *pmx_profile_add_vpn(pmx_profile *pf);
pmx_vpn *pmx_profile_find_vpn(pmx_profile *pf, pmx_id id);
pmx_status pmx_profile_remove_vpn(pmx_profile *pf, pmx_id id);
/* Import a .ovpn/.conf from disk and append it. Returns the new entry. */
pmx_status pmx_profile_import_vpn(pmx_profile *pf, const char *path,
                                  pmx_vpn **out);

/* Human label for a rule target (proxy/chain), e.g. for the rules table.
 * Writes "—" for PMX_TARGET_NONE and "(missing)" for a dangling id. */
void pmx_profile_target_label(const pmx_profile *pf, pmx_target_kind kind,
                              pmx_id id, char *buf, size_t buf_size);

/* Validate references (rule targets resolve, chain hops resolve, port specs
 * parse). Returns PMX_OK or the first problem; *msg (optional) explains. */
pmx_status pmx_profile_validate(const pmx_profile *pf, char *msg, size_t msg_size);

/* --- persistence (JSON) ------------------------------------------------- */
pmx_status pmx_profile_save(const pmx_profile *pf, const char *path);
pmx_status pmx_profile_load(pmx_profile *pf, const char *path);

/* Serialize/parse to an in-memory string (used by save/load and tests). Caller
 * frees *out with pmx_profile_string_free. */
pmx_status pmx_profile_to_json(const pmx_profile *pf, char **out);
pmx_status pmx_profile_from_json(pmx_profile *pf, const char *json);
void pmx_profile_string_free(char *s);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_PROFILE_H */
