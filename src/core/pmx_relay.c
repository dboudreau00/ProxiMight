#include "proximight/pmx_relay.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_log.h"

#include <stdlib.h>
#include <string.h>

#define PMX_RELAY_MAX_CONNS 64
/* Entries carry a whole proxy chain, so keep the pending table modest — a SYN
 * only waits here for the milliseconds until the relay accepts it. */
#define PMX_RELAY_MAX_PENDING 64
#define PMX_RELAY_ENTRY_TTL_MS 30000
#define PMX_RELAY_SPLICE_TICK_MS 500 /* how fast a stop() is noticed */
#define PMX_RELAY_IO_TIMEOUT_MS 10000
#define PMX_RELAY_BUF 8192

/* A pending "this source port was really headed there" record. */
typedef struct relay_entry {
    pmx_port src_port;
    char dst_host[PMX_MAX_HOST];
    pmx_port dst_port;
    pmx_proxy chain[PMX_MAX_CHAIN_HOPS];
    size_t chain_len;
    uint64_t added_ms;
} relay_entry;

typedef struct relay_conn {
    pmx_relay *relay;
    pmx_socket client;
    pmx_port src_port; /* the flow's source port == NAT key, for the close cb */
    char dst_host[PMX_MAX_HOST];
    pmx_port dst_port;
    pmx_proxy chain[PMX_MAX_CHAIN_HOPS];
    size_t chain_len;
    pmx_thread *thread;
    bool done;
} relay_conn;

struct pmx_relay {
    pmx_socket listener;
    pmx_port port;

    pmx_mutex *mutex;
    pmx_thread *accept_thread;
    bool running;

    /* Set once before traffic starts; read by worker threads. */
    pmx_relay_close_cb close_cb;
    void *close_user;

    relay_entry pending[PMX_RELAY_MAX_PENDING];
    size_t pending_count;

    relay_conn *conns[PMX_RELAY_MAX_CONNS];
    size_t conn_count;

    uint64_t stat_ok;
    uint64_t stat_failed;
};

static bool relay_running(pmx_relay *r) {
    pmx_mutex_lock(r->mutex);
    bool v = r->running;
    pmx_mutex_unlock(r->mutex);
    return v;
}

/* Caller must hold the lock. */
static void expire_locked(pmx_relay *r) {
    uint64_t now = pmx_now_ms();
    size_t w = 0;
    for (size_t i = 0; i < r->pending_count; i++) {
        if (now - r->pending[i].added_ms < PMX_RELAY_ENTRY_TTL_MS) {
            r->pending[w++] = r->pending[i];
        }
    }
    r->pending_count = w;
}

pmx_status pmx_relay_register(pmx_relay *r, pmx_port src_port,
                              const char *dst_host, pmx_port dst_port,
                              const pmx_proxy *chain, size_t chain_len) {
    if (r == NULL || dst_host == NULL || chain == NULL || src_port == 0 ||
        chain_len == 0 || chain_len > PMX_MAX_CHAIN_HOPS) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_mutex_lock(r->mutex);
    expire_locked(r);

    relay_entry *slot = NULL;
    for (size_t i = 0; i < r->pending_count; i++) {
        if (r->pending[i].src_port == src_port) {
            slot = &r->pending[i]; /* replace a stale entry for this port */
            break;
        }
    }
    if (slot == NULL) {
        if (r->pending_count >= PMX_RELAY_MAX_PENDING) {
            pmx_mutex_unlock(r->mutex);
            return PMX_ERR_STATE;
        }
        slot = &r->pending[r->pending_count++];
    }
    memset(slot, 0, sizeof(*slot));
    slot->src_port = src_port;
    pmx_strlcpy(slot->dst_host, dst_host, sizeof(slot->dst_host));
    slot->dst_port = dst_port;
    for (size_t i = 0; i < chain_len; i++) {
        slot->chain[i] = chain[i];
    }
    slot->chain_len = chain_len;
    slot->added_ms = pmx_now_ms();
    pmx_mutex_unlock(r->mutex);
    return PMX_OK;
}

/* Consume the entry for `src_port`, if any. */
static bool relay_take(pmx_relay *r, pmx_port src_port, relay_entry *out) {
    bool found = false;
    pmx_mutex_lock(r->mutex);
    expire_locked(r);
    for (size_t i = 0; i < r->pending_count; i++) {
        if (r->pending[i].src_port == src_port) {
            *out = r->pending[i];
            for (size_t j = i; j + 1 < r->pending_count; j++) {
                r->pending[j] = r->pending[j + 1];
            }
            r->pending_count--;
            found = true;
            break;
        }
    }
    pmx_mutex_unlock(r->mutex);
    return found;
}

/* Pull finished connections out of the table, then join them OUTSIDE the lock
 * (a worker takes the lock on its way out, so joining while holding it would
 * deadlock). */
static void relay_reap(pmx_relay *r, bool all) {
    relay_conn *harvest[PMX_RELAY_MAX_CONNS];
    size_t n = 0;

    pmx_mutex_lock(r->mutex);
    size_t w = 0;
    for (size_t i = 0; i < r->conn_count; i++) {
        relay_conn *c = r->conns[i];
        if ((all || c->done) && n < PMX_RELAY_MAX_CONNS) {
            harvest[n++] = c;
        } else {
            r->conns[w++] = c;
        }
    }
    r->conn_count = w;
    pmx_mutex_unlock(r->mutex);

    for (size_t i = 0; i < n; i++) {
        if (harvest[i]->thread != NULL) {
            pmx_thread_join(harvest[i]->thread);
        }
        free(harvest[i]);
    }
}

static void relay_conn_worker(void *arg) {
    relay_conn *rc = (relay_conn *)arg;
    pmx_relay *r = rc->relay;

    /* Connect to the first hop, then ask each hop to reach the next one, and
     * the last hop for the real destination. Every handshake rides inside the
     * tunnel established by the previous one, which is what makes a chain a
     * chain rather than a sequence of independent hops. */
    pmx_socket up = PMX_INVALID_SOCKET;
    pmx_status st = pmx_tcp_connect(rc->chain[0].host, rc->chain[0].port,
                                    PMX_RELAY_IO_TIMEOUT_MS, &up);
    size_t failed_hop = 0;
    for (size_t i = 0; st == PMX_OK && i < rc->chain_len; i++) {
        const char *next_host;
        pmx_port next_port;
        if (i + 1 < rc->chain_len) {
            next_host = rc->chain[i + 1].host;
            next_port = rc->chain[i + 1].port;
        } else {
            next_host = rc->dst_host;
            next_port = rc->dst_port;
        }
        st = pmx_proxy_handshake(up, &rc->chain[i], next_host, next_port,
                                 PMX_RELAY_IO_TIMEOUT_MS);
        if (st != PMX_OK) {
            failed_hop = i;
        }
    }
    if (st != PMX_OK) {
        PMX_LOGW("[relay] %s:%u failed at hop %zu/%zu ('%s'): %s", rc->dst_host,
                 (unsigned)rc->dst_port, failed_hop + 1, rc->chain_len,
                 rc->chain[failed_hop].label, pmx_status_str(st));
        if (up != PMX_INVALID_SOCKET) {
            pmx_socket_close(up);
        }
        pmx_socket_close(rc->client);
        pmx_mutex_lock(r->mutex);
        r->stat_failed++;
        rc->done = true;
        pmx_mutex_unlock(r->mutex);
        if (r->close_cb != NULL) {
            r->close_cb(r->close_user, rc->src_port);
        }
        return;
    }

    PMX_LOGD("[relay] %s:%u established through %zu hop(s), first '%s'",
             rc->dst_host, (unsigned)rc->dst_port, rc->chain_len,
             rc->chain[0].label);
    pmx_mutex_lock(r->mutex);
    r->stat_ok++;
    pmx_mutex_unlock(r->mutex);

    /* Splice until either side closes or the relay is stopped. */
    char buf[PMX_RELAY_BUF];
    for (;;) {
        int m = pmx_wait_two(rc->client, up, PMX_RELAY_SPLICE_TICK_MS);
        if (m < 0) {
            break;
        }
        if (m == 0) {
            if (!relay_running(r)) {
                break; /* shutdown noticed within one tick */
            }
            continue;
        }
        size_t got = 0;
        if (m & 1) {
            if (pmx_recv_some(rc->client, buf, sizeof(buf), &got,
                              PMX_RELAY_IO_TIMEOUT_MS) != PMX_OK) {
                break;
            }
            if (pmx_send_all(up, buf, got) != PMX_OK) {
                break;
            }
        }
        if (m & 2) {
            if (pmx_recv_some(up, buf, sizeof(buf), &got,
                              PMX_RELAY_IO_TIMEOUT_MS) != PMX_OK) {
                break;
            }
            if (pmx_send_all(rc->client, buf, got) != PMX_OK) {
                break;
            }
        }
    }

    pmx_socket_close(up);
    pmx_socket_close(rc->client);
    pmx_mutex_lock(r->mutex);
    rc->done = true;
    pmx_mutex_unlock(r->mutex);
    if (r->close_cb != NULL) {
        r->close_cb(r->close_user, rc->src_port);
    }
}

static void relay_accept_worker(void *arg) {
    pmx_relay *r = (pmx_relay *)arg;
    pmx_socket listener = r->listener; /* captured: stop() closes it to unblock */

    while (relay_running(r)) {
        pmx_socket client = PMX_INVALID_SOCKET;
        pmx_port peer_port = 0;
        if (pmx_tcp_accept(listener, &client, &peer_port) != PMX_OK) {
            if (!relay_running(r)) {
                break;
            }
            pmx_sleep_ms(10);
            continue;
        }

        relay_reap(r, false);

        relay_entry e;
        if (!relay_take(r, peer_port, &e)) {
            PMX_LOGW("[relay] no destination registered for source port %u — "
                     "dropping (a redirect arrived without a mapping)",
                     (unsigned)peer_port);
            pmx_socket_close(client);
            pmx_mutex_lock(r->mutex);
            r->stat_failed++;
            pmx_mutex_unlock(r->mutex);
            continue;
        }

        relay_conn *rc = (relay_conn *)calloc(1, sizeof(*rc));
        if (rc == NULL) {
            pmx_socket_close(client);
            continue;
        }
        rc->relay = r;
        rc->client = client;
        rc->src_port = e.src_port; /* == peer_port; the NAT key for this flow */
        pmx_strlcpy(rc->dst_host, e.dst_host, sizeof(rc->dst_host));
        rc->dst_port = e.dst_port;
        for (size_t i = 0; i < e.chain_len; i++) {
            rc->chain[i] = e.chain[i];
        }
        rc->chain_len = e.chain_len;

        bool room;
        pmx_mutex_lock(r->mutex);
        room = (r->conn_count < PMX_RELAY_MAX_CONNS);
        if (room) {
            r->conns[r->conn_count++] = rc;
        } else {
            r->stat_failed++;
        }
        pmx_mutex_unlock(r->mutex);

        if (!room) {
            PMX_LOGW("[relay] connection table full — dropping");
            pmx_socket_close(client);
            free(rc);
            continue;
        }
        if (pmx_thread_start(relay_conn_worker, rc, &rc->thread) != PMX_OK) {
            PMX_LOGE("[relay] failed to start worker thread");
            pmx_socket_close(client);
            pmx_mutex_lock(r->mutex);
            rc->done = true;
            r->stat_failed++;
            pmx_mutex_unlock(r->mutex);
        }
    }
}

pmx_status pmx_relay_start(pmx_relay **out, pmx_port port) {
    if (out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = NULL;

    pmx_relay *r = (pmx_relay *)calloc(1, sizeof(*r));
    if (r == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    r->listener = PMX_INVALID_SOCKET;
    r->mutex = pmx_mutex_create();
    if (r->mutex == NULL) {
        free(r);
        return PMX_ERR_NO_MEMORY;
    }

    pmx_net_init();
    pmx_status st = pmx_tcp_listen("127.0.0.1", port, &r->listener, &r->port);
    if (st != PMX_OK) {
        pmx_mutex_destroy(r->mutex);
        pmx_net_shutdown();
        free(r);
        return st;
    }

    r->running = true;
    if (pmx_thread_start(relay_accept_worker, r, &r->accept_thread) != PMX_OK) {
        pmx_socket_close(r->listener);
        pmx_mutex_destroy(r->mutex);
        pmx_net_shutdown();
        free(r);
        return PMX_ERR_STATE;
    }

    PMX_LOGI("[relay] listening on 127.0.0.1:%u", (unsigned)r->port);
    *out = r;
    return PMX_OK;
}

void pmx_relay_stop(pmx_relay *r) {
    if (r == NULL) {
        return;
    }
    pmx_mutex_lock(r->mutex);
    r->running = false;
    pmx_socket lis = r->listener;
    r->listener = PMX_INVALID_SOCKET;
    pmx_mutex_unlock(r->mutex);

    /* Closing the listener unblocks the accept() the worker is parked in. */
    if (lis != PMX_INVALID_SOCKET) {
        pmx_socket_close(lis);
    }
    if (r->accept_thread != NULL) {
        pmx_thread_join(r->accept_thread);
        r->accept_thread = NULL;
    }

    /* Workers notice !running within one splice tick and close their own
     * sockets, so nothing is closed from another thread. */
    for (int spins = 0; spins < 40; spins++) {
        relay_reap(r, false);
        pmx_mutex_lock(r->mutex);
        size_t left = r->conn_count;
        pmx_mutex_unlock(r->mutex);
        if (left == 0) {
            break;
        }
        pmx_sleep_ms(50);
    }
    relay_reap(r, true); /* join any stragglers */

    PMX_LOGI("[relay] stopped (%llu proxied, %llu failed)",
             (unsigned long long)r->stat_ok, (unsigned long long)r->stat_failed);
    pmx_mutex_destroy(r->mutex);
    pmx_net_shutdown();
    free(r);
}

pmx_port pmx_relay_port(const pmx_relay *r) { return r ? r->port : 0; }

void pmx_relay_set_close_cb(pmx_relay *r, pmx_relay_close_cb cb, void *user) {
    if (r == NULL) {
        return;
    }
    /* Set once before the pumps start; workers read it without locking. */
    r->close_cb = cb;
    r->close_user = user;
}

size_t pmx_relay_active(pmx_relay *r) {
    if (r == NULL) {
        return 0;
    }
    pmx_mutex_lock(r->mutex);
    size_t n = r->conn_count;
    pmx_mutex_unlock(r->mutex);
    return n;
}

void pmx_relay_stats(pmx_relay *r, uint64_t *out_ok, uint64_t *out_failed) {
    if (r == NULL) {
        return;
    }
    pmx_mutex_lock(r->mutex);
    if (out_ok != NULL) {
        *out_ok = r->stat_ok;
    }
    if (out_failed != NULL) {
        *out_failed = r->stat_failed;
    }
    pmx_mutex_unlock(r->mutex);
}
