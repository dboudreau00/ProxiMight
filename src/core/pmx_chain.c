#include "proximight/pmx_chain.h"

#include <string.h>

void pmx_chain_init(pmx_chain *c) {
    if (c == NULL) {
        return;
    }
    memset(c, 0, sizeof(*c));
    c->mode = PMX_CHAIN_SEQUENTIAL;
    c->enabled = true;
    pmx_strlcpy(c->label, "New chain", sizeof(c->label));
}

const char *pmx_chain_mode_str(pmx_chain_mode m) {
    switch (m) {
    case PMX_CHAIN_SEQUENTIAL: return "Sequential";
    case PMX_CHAIN_REDUNDANCY: return "Redundancy";
    case PMX_CHAIN_MODE__COUNT: break;
    }
    return "?";
}

pmx_status pmx_chain_add_hop(pmx_chain *c, pmx_id proxy_id) {
    if (c == NULL || proxy_id == PMX_ID_NONE) {
        return PMX_ERR_INVALID_ARG;
    }
    if (c->hop_count >= PMX_MAX_CHAIN_HOPS) {
        return PMX_ERR_STATE;
    }
    c->hops[c->hop_count++] = proxy_id;
    return PMX_OK;
}

pmx_status pmx_chain_remove_hop(pmx_chain *c, size_t index) {
    if (c == NULL || index >= c->hop_count) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t i = index; i + 1 < c->hop_count; i++) {
        c->hops[i] = c->hops[i + 1];
    }
    c->hop_count--;
    return PMX_OK;
}

pmx_status pmx_chain_move_hop(pmx_chain *c, size_t from, size_t to) {
    if (c == NULL || from >= c->hop_count || to >= c->hop_count) {
        return PMX_ERR_INVALID_ARG;
    }
    if (from == to) {
        return PMX_OK;
    }
    pmx_id moved = c->hops[from];
    if (from < to) {
        for (size_t i = from; i < to; i++) {
            c->hops[i] = c->hops[i + 1];
        }
    } else {
        for (size_t i = from; i > to; i--) {
            c->hops[i] = c->hops[i - 1];
        }
    }
    c->hops[to] = moved;
    return PMX_OK;
}
