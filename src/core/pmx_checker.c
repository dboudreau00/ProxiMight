#include "proximight/pmx_checker.h"
#include "proximight/pmx_netpath.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void pmx_check_opts_defaults(pmx_check_opts *opts) {
    if (opts == NULL) {
        return;
    }
    memset(opts, 0, sizeof(*opts));
    pmx_strlcpy(opts->probe_host, "example.com", sizeof(opts->probe_host));
    opts->probe_port = 443;
    opts->timeout_ms = 5000;
    opts->measure_egress_ip = false;
    pmx_strlcpy(opts->egress_service, "api.ipify.org", sizeof(opts->egress_service));
    pmx_strlcpy(opts->egress_path, "/", sizeof(opts->egress_path));
    opts->measure_ping = true;
}

/* Optional: fetch our egress IP by tunneling an HTTP GET through the proxy. */
static void measure_egress(const pmx_proxy *p, const pmx_check_opts *opts,
                           char *ip_out, size_t ip_cap) {
    ip_out[0] = '\0';
    if (opts->egress_service[0] == '\0') {
        return;
    }
    pmx_socket s = PMX_INVALID_SOCKET;
    if (pmx_tcp_connect(p->host, p->port, opts->timeout_ms, &s) != PMX_OK) {
        return;
    }
    if (pmx_proxy_handshake(s, p, opts->egress_service, 80, opts->timeout_ms) !=
        PMX_OK) {
        pmx_socket_close(s);
        return;
    }
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: ProxiMight/checker\r\nConnection: close\r\n\r\n",
                     opts->egress_path[0] ? opts->egress_path : "/",
                     opts->egress_service);
    if (n > 0 && pmx_send_all(s, req, (size_t)n) == PMX_OK) {
        char resp[2048];
        size_t total = 0;
        for (int i = 0; i < 8 && total < sizeof(resp) - 1; i++) {
            size_t got = 0;
            if (pmx_recv_some(s, resp + total, sizeof(resp) - 1 - total, &got,
                              opts->timeout_ms) != PMX_OK) {
                break;
            }
            total += got;
        }
        resp[total] = '\0';
        const char *body = strstr(resp, "\r\n\r\n");
        if (body != NULL) {
            body += 4;
            while (*body == ' ' || *body == '\r' || *body == '\n') body++;
            size_t j = 0;
            while (body[j] != '\0' && body[j] != '\r' && body[j] != '\n' &&
                   body[j] != ' ' && j + 1 < ip_cap) {
                ip_out[j] = body[j];
                j++;
            }
            ip_out[j] = '\0';
        }
    }
    pmx_socket_close(s);
}

pmx_status pmx_check_proxy(const pmx_proxy *p, const pmx_check_opts *opts,
                           pmx_check_result *out) {
    if (p == NULL || opts == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->proxy_id = p->id;
    out->hop_index = -1;
    out->latency_ms = -1;
    out->ping_ms = -1;

    pmx_net_init();

    /* ICMP round-trip to the proxy host. This is the raw network latency to the
     * box, separate from the TCP+handshake time measured below; comparing the
     * two tells you whether slowness is the network or the proxy itself. */
    if (opts->measure_ping) {
        pmx_ping_result pr;
        int ping_timeout = opts->timeout_ms > 1500 ? 1500 : opts->timeout_ms;
        if (pmx_ping(p->host, 0, ping_timeout, &pr) == PMX_OK && pr.reachable) {
            out->ping_ms = pr.rtt_ms;
        }
    }

    uint64_t start = pmx_now_ms();

    pmx_socket s = PMX_INVALID_SOCKET;
    pmx_status st = pmx_tcp_connect(p->host, p->port, opts->timeout_ms, &s);
    if (st != PMX_OK) {
        out->reachable = false;
        out->status = st;
        snprintf(out->message, sizeof(out->message), "unreachable: %s",
                 pmx_status_str(st));
        out->checked_at_ms = pmx_now_ms();
        pmx_net_shutdown();
        return st;
    }
    out->reachable = true;

    st = pmx_proxy_handshake(s, p, opts->probe_host, opts->probe_port,
                             opts->timeout_ms);
    pmx_socket_close(s);

    out->latency_ms = (int)(pmx_now_ms() - start);
    out->handshake_ok = (st == PMX_OK);
    out->status = st;

    if (st == PMX_OK) {
        snprintf(out->message, sizeof(out->message), "OK via %s — %d ms",
                 pmx_proxy_type_str(p->type), out->latency_ms);
        if (opts->measure_egress_ip) {
            measure_egress(p, opts, out->egress_ip, sizeof(out->egress_ip));
        }
    } else {
        snprintf(out->message, sizeof(out->message), "reachable, but %s",
                 pmx_status_str(st));
    }
    out->checked_at_ms = pmx_now_ms();
    pmx_net_shutdown();
    return st;
}

/* ------------------------------------------------------------ async checker */

typedef struct check_job {
    pmx_proxy proxy;
    int hop_index;
    struct check_job *next;
} check_job;

typedef struct result_node {
    pmx_check_result result;
    struct result_node *next;
} result_node;

struct pmx_checker {
    pmx_check_opts opts;
    pmx_mutex *mutex;
    pmx_cond *cond;
    pmx_thread *worker;
    bool running;

    check_job *job_head, *job_tail;
    result_node *res_head, *res_tail;
    size_t pending;
};

static check_job *dequeue_job(pmx_checker *chk) {
    check_job *j = chk->job_head;
    if (j != NULL) {
        chk->job_head = j->next;
        if (chk->job_head == NULL) {
            chk->job_tail = NULL;
        }
    }
    return j;
}

static void push_result(pmx_checker *chk, const pmx_check_result *r) {
    result_node *n = (result_node *)calloc(1, sizeof(*n));
    if (n == NULL) {
        return;
    }
    n->result = *r;
    if (chk->res_tail != NULL) {
        chk->res_tail->next = n;
    } else {
        chk->res_head = n;
    }
    chk->res_tail = n;
}

static void checker_worker(void *arg) {
    pmx_checker *chk = (pmx_checker *)arg;
    for (;;) {
        pmx_mutex_lock(chk->mutex);
        while (chk->running && chk->job_head == NULL) {
            pmx_cond_wait(chk->cond, chk->mutex);
        }
        /* Shutting down: ABANDON whatever is still queued rather than draining
         * it. The exit test used to be (!running && job_head == NULL), so
         * clearing `running` only stopped the worker waiting for MORE work — it
         * still ran the entire backlog first, while pmx_checker_destroy blocked
         * on the join. Queue eight checks against blackholed hosts, then close
         * the window, and the GUI thread froze for the whole backlog (~6.5 s
         * each) with no cancel. destroy() frees the abandoned jobs. */
        if (!chk->running) {
            pmx_mutex_unlock(chk->mutex);
            break;
        }
        check_job *job = dequeue_job(chk);
        pmx_check_opts opts = chk->opts;
        pmx_mutex_unlock(chk->mutex);

        if (job == NULL) {
            continue;
        }
        pmx_check_result r;
        pmx_check_proxy(&job->proxy, &opts, &r);
        r.hop_index = job->hop_index;
        r.proxy_id = job->proxy.id;

        pmx_mutex_lock(chk->mutex);
        push_result(chk, &r);
        if (chk->pending > 0) {
            chk->pending--;
        }
        pmx_mutex_unlock(chk->mutex);
        free(job);
    }
}

pmx_checker *pmx_checker_create(const pmx_check_opts *opts) {
    pmx_checker *chk = (pmx_checker *)calloc(1, sizeof(*chk));
    if (chk == NULL) {
        return NULL;
    }
    if (opts != NULL) {
        chk->opts = *opts;
    } else {
        pmx_check_opts_defaults(&chk->opts);
    }
    chk->mutex = pmx_mutex_create();
    chk->cond = pmx_cond_create();
    if (chk->mutex == NULL || chk->cond == NULL) {
        pmx_mutex_destroy(chk->mutex);
        pmx_cond_destroy(chk->cond);
        free(chk);
        return NULL;
    }
    chk->running = true;
    if (pmx_thread_start(checker_worker, chk, &chk->worker) != PMX_OK) {
        pmx_mutex_destroy(chk->mutex);
        pmx_cond_destroy(chk->cond);
        free(chk);
        return NULL;
    }
    return chk;
}

void pmx_checker_destroy(pmx_checker *chk) {
    if (chk == NULL) {
        return;
    }
    pmx_mutex_lock(chk->mutex);
    chk->running = false;
    pmx_cond_broadcast(chk->cond);
    pmx_mutex_unlock(chk->mutex);
    pmx_thread_join(chk->worker);

    check_job *j = chk->job_head;
    while (j != NULL) {
        check_job *nx = j->next;
        free(j);
        j = nx;
    }
    result_node *r = chk->res_head;
    while (r != NULL) {
        result_node *nx = r->next;
        free(r);
        r = nx;
    }
    pmx_mutex_destroy(chk->mutex);
    pmx_cond_destroy(chk->cond);
    free(chk);
}

void pmx_checker_set_opts(pmx_checker *chk, const pmx_check_opts *opts) {
    if (chk == NULL || opts == NULL) {
        return;
    }
    pmx_mutex_lock(chk->mutex);
    chk->opts = *opts;
    pmx_mutex_unlock(chk->mutex);
}

static pmx_status enqueue_job(pmx_checker *chk, const pmx_proxy *p, int hop) {
    check_job *job = (check_job *)calloc(1, sizeof(*job));
    if (job == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    job->proxy = *p;
    job->hop_index = hop;
    pmx_mutex_lock(chk->mutex);
    if (chk->job_tail != NULL) {
        chk->job_tail->next = job;
    } else {
        chk->job_head = job;
    }
    chk->job_tail = job;
    chk->pending++;
    pmx_cond_signal(chk->cond);
    pmx_mutex_unlock(chk->mutex);
    return PMX_OK;
}

pmx_status pmx_checker_submit(pmx_checker *chk, const pmx_proxy *p) {
    if (chk == NULL || p == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    return enqueue_job(chk, p, -1);
}

pmx_status pmx_checker_submit_chain(pmx_checker *chk, const pmx_chain *c,
                                    const pmx_proxy *proxies, size_t count) {
    if (chk == NULL || c == NULL || proxies == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    for (size_t h = 0; h < c->hop_count; h++) {
        const pmx_proxy *found = NULL;
        for (size_t i = 0; i < count; i++) {
            if (proxies[i].id == c->hops[h]) {
                found = &proxies[i];
                break;
            }
        }
        if (found != NULL) {
            enqueue_job(chk, found, (int)h);
        }
    }
    return PMX_OK;
}

bool pmx_checker_poll(pmx_checker *chk, pmx_check_result *out) {
    if (chk == NULL || out == NULL) {
        return false;
    }
    pmx_mutex_lock(chk->mutex);
    result_node *n = chk->res_head;
    if (n != NULL) {
        chk->res_head = n->next;
        if (chk->res_head == NULL) {
            chk->res_tail = NULL;
        }
    }
    pmx_mutex_unlock(chk->mutex);
    if (n == NULL) {
        return false;
    }
    *out = n->result;
    free(n);
    return true;
}

size_t pmx_checker_pending(pmx_checker *chk) {
    if (chk == NULL) {
        return 0;
    }
    pmx_mutex_lock(chk->mutex);
    size_t p = chk->pending;
    pmx_mutex_unlock(chk->mutex);
    return p;
}
