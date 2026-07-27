#include "proximight/pmx_nat.h"
#include "proximight/pmx_thread.h"

#include <stdlib.h>
#include <string.h>

typedef struct nat_slot {
    bool used;
    /* The relay side of this flow has finished. The mapping is KEPT (so late
     * packets from the app are still rewritten to the relay instead of leaking
     * straight to the real destination) but the slot may be reclaimed under
     * pressure ahead of any live flow. */
    bool closed;
    /* Last time this mapping was actually USED (looked up by either pump).
     *
     * The TTL is measured against this, not against e.created_ms. Measuring
     * against creation meant a mapping hard-expired `ttl_ms` after the CONNECT
     * even while its flow was fully alive — and a live flow whose mapping has
     * gone stops being rewritten, so the application's next segment egresses
     * DIRECT to the real destination from the real source IP. That is the exact
     * proxy bypass this table's eviction policy is written to prevent, arrived at
     * through the clock instead of through eviction. Any flow that outlived the
     * TTL (a long download, SSH, a websocket) hit it. */
    uint64_t last_seen_ms;
    pmx_nat_entry e;
} nat_slot;

struct pmx_nat {
    nat_slot *slots;
    size_t capacity;
    size_t count;
    int ttl_ms;
    pmx_mutex *mutex; /* the socket and network pumps are different threads */
};

pmx_nat *pmx_nat_create(size_t capacity, int ttl_ms) {
    if (capacity == 0) {
        capacity = 512;
    }
    pmx_nat *n = (pmx_nat *)calloc(1, sizeof(*n));
    if (n == NULL) {
        return NULL;
    }
    n->slots = (nat_slot *)calloc(capacity, sizeof(nat_slot));
    if (n->slots == NULL) {
        free(n);
        return NULL;
    }
    n->mutex = pmx_mutex_create();
    if (n->mutex == NULL) {
        free(n->slots);
        free(n);
        return NULL;
    }
    n->capacity = capacity;
    n->ttl_ms = (ttl_ms > 0) ? ttl_ms : 120000;
    return n;
}

void pmx_nat_destroy(pmx_nat *n) {
    if (n == NULL) {
        return;
    }
    pmx_mutex_destroy(n->mutex);
    free(n->slots);
    free(n);
}

/* Expiry is INACTIVITY, not age. See nat_slot::last_seen_ms for why. An entry
 * that is never looked up still expires ttl_ms after it was added, which is the
 * case this was originally written for: a SYN that got dropped. */
static bool expired(const pmx_nat *n, const nat_slot *s, uint64_t now_ms) {
    return (now_ms > s->last_seen_ms) &&
           ((now_ms - s->last_seen_ms) > (uint64_t)n->ttl_ms);
}

/* Caller holds the lock. */
static nat_slot *find_slot(pmx_nat *n, pmx_port src_port) {
    for (size_t i = 0; i < n->capacity; i++) {
        if (n->slots[i].used && n->slots[i].e.src_port == src_port) {
            return &n->slots[i];
        }
    }
    return NULL;
}

pmx_status pmx_nat_add(pmx_nat *n, uint32_t src_addr, pmx_port src_port,
                       uint32_t orig_dst_addr, pmx_port orig_dst_port,
                       uint64_t now_ms) {
    if (n == NULL || src_port == 0) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_mutex_lock(n->mutex);

    /* Source ports are recycled by the OS, so an existing entry for this port
     * is stale by definition — replace it rather than leaving two. */
    nat_slot *slot = find_slot(n, src_port);
    if (slot == NULL) {
        /* Prefer a free slot; otherwise reclaim the oldest EXPIRED one. We never
         * evict a live entry: for a long-lived flow the oldest entry is an
         * ACTIVE connection, and dropping its mapping would make wd_net_pump's
         * pmx_nat_find() miss, so its packets would stop being rewritten and
         * egress DIRECT to the real destination — a silent proxy bypass. When
         * the table is full of live flows we fail closed (PMX_ERR_STATE) so the
         * caller blocks the NEW connection instead of un-proxying an old one.
         * Finished flows are marked via pmx_nat_mark_closed when their relay
         * connection ends — they keep matching (so late packets from the app are
         * still rewritten rather than leaking direct) but become reclaimable, so
         * this only bites above `capacity` genuinely-concurrent LIVE flows. */
        nat_slot *reclaim = NULL;
        for (size_t i = 0; i < n->capacity; i++) {
            if (!n->slots[i].used) {
                slot = &n->slots[i];
                slot->used = true;
                n->count++;
                break;
            }
            /* Reclaimable = expired, or a flow whose relay side already
             * finished. Never a live one. */
            if ((expired(n, &n->slots[i], now_ms) || n->slots[i].closed) &&
                (reclaim == NULL ||
                 n->slots[i].e.created_ms < reclaim->e.created_ms)) {
                reclaim = &n->slots[i];
            }
        }
        if (slot == NULL) {
            slot = reclaim; /* stays NULL if the table is full of live entries */
        }
    }
    if (slot == NULL) {
        pmx_mutex_unlock(n->mutex);
        return PMX_ERR_STATE; /* full of live flows: fail closed, never leak */
    }

    slot->used = true;
    slot->closed = false; /* reused slot starts live */
    slot->last_seen_ms = now_ms;
    slot->e.src_addr = src_addr;
    slot->e.src_port = src_port;
    slot->e.orig_dst_addr = orig_dst_addr;
    slot->e.orig_dst_port = orig_dst_port;
    slot->e.created_ms = now_ms;
    pmx_mutex_unlock(n->mutex);
    return PMX_OK;
}

bool pmx_nat_find(pmx_nat *n, pmx_port src_port, uint64_t now_ms,
                  pmx_nat_entry *out) {
    if (n == NULL || src_port == 0) {
        return false;
    }
    bool ok = false;
    pmx_mutex_lock(n->mutex);
    nat_slot *slot = find_slot(n, src_port);
    if (slot != NULL && !expired(n, slot, now_ms)) {
        if (out != NULL) {
            *out = slot->e;
        }
        /* A lookup IS the activity that keeps a mapping alive, so refresh the
         * idle timer — but only for a live flow. Refreshing a `closed` entry
         * would let late packets to a dead flow pin its slot forever, and the
         * whole point of the closed state is that the slot stays reclaimable. */
        if (!slot->closed) {
            slot->last_seen_ms = now_ms;
        }
        ok = true;
    }
    pmx_mutex_unlock(n->mutex);
    return ok;
}

void pmx_nat_mark_closed(pmx_nat *n, pmx_port src_port) {
    if (n == NULL || src_port == 0) {
        return;
    }
    pmx_mutex_lock(n->mutex);
    nat_slot *slot = find_slot(n, src_port);
    if (slot != NULL) {
        slot->closed = true;
    }
    pmx_mutex_unlock(n->mutex);
}

void pmx_nat_remove(pmx_nat *n, pmx_port src_port) {
    if (n == NULL) {
        return;
    }
    pmx_mutex_lock(n->mutex);
    nat_slot *slot = find_slot(n, src_port);
    if (slot != NULL) {
        slot->used = false;
        slot->closed = false;
        slot->last_seen_ms = 0;
        memset(&slot->e, 0, sizeof(slot->e));
        if (n->count > 0) {
            n->count--;
        }
    }
    pmx_mutex_unlock(n->mutex);
}

size_t pmx_nat_expire(pmx_nat *n, uint64_t now_ms) {
    if (n == NULL) {
        return 0;
    }
    size_t dropped = 0;
    pmx_mutex_lock(n->mutex);
    for (size_t i = 0; i < n->capacity; i++) {
        if (n->slots[i].used && expired(n, &n->slots[i], now_ms)) {
            n->slots[i].used = false;
            n->slots[i].closed = false;
            n->slots[i].last_seen_ms = 0;
            memset(&n->slots[i].e, 0, sizeof(n->slots[i].e));
            if (n->count > 0) {
                n->count--;
            }
            dropped++;
        }
    }
    pmx_mutex_unlock(n->mutex);
    return dropped;
}

size_t pmx_nat_count(pmx_nat *n) {
    if (n == NULL) {
        return 0;
    }
    pmx_mutex_lock(n->mutex);
    size_t c = n->count;
    pmx_mutex_unlock(n->mutex);
    return c;
}
