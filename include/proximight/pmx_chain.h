/*
 * pmx_chain.h — proxy chains.
 *
 * SEQUENTIAL: tunnel through every hop in order (hop0 -> hop1 -> ... -> target).
 *             Fully implemented: each handshake rides inside the tunnel the
 *             previous hop established (see test_relay_chain).
 * REDUNDANCY: hops are interchangeable alternatives rather than a path.
 *
 * NOT YET IMPLEMENTED for REDUNDANCY: health-based selection and failover.
 * Resolution takes hop 0 unconditionally and never asks whether it is reachable,
 * so a redundancy chain currently behaves like a one-hop chain. If that hop is
 * down the flow fails closed — safe, but not the continuity the name promises.
 * Making it real means feeding pmx_checker's health into pmx_engine's resolve
 * step; until then do not describe this as failover in the UI or docs.
 */
#ifndef PROXIMIGHT_PMX_CHAIN_H
#define PROXIMIGHT_PMX_CHAIN_H

#include "proximight/pmx_types.h"
#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef enum pmx_chain_mode {
    PMX_CHAIN_SEQUENTIAL = 0,
    PMX_CHAIN_REDUNDANCY,
    PMX_CHAIN_MODE__COUNT
} pmx_chain_mode;

typedef struct pmx_chain {
    pmx_id id;
    char label[PMX_MAX_LABEL];
    pmx_chain_mode mode;
    pmx_id hops[PMX_MAX_CHAIN_HOPS]; /* proxy ids, in order */
    size_t hop_count;
    bool enabled;
} pmx_chain;

void pmx_chain_init(pmx_chain *c);
const char *pmx_chain_mode_str(pmx_chain_mode m);

pmx_status pmx_chain_add_hop(pmx_chain *c, pmx_id proxy_id);
pmx_status pmx_chain_remove_hop(pmx_chain *c, size_t index);
pmx_status pmx_chain_move_hop(pmx_chain *c, size_t from, size_t to);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_CHAIN_H */
