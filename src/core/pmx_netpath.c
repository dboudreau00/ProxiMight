#include "proximight/pmx_netpath.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>

void pmx_path_opts_defaults(pmx_path_opts *out) {
    if (out == NULL) {
        return;
    }
    out->max_hops = PMX_MAX_HOPS;
    out->cycles = 3;
    out->timeout_ms = 1000;
    out->payload_size = 32;
    out->resolve_names = false;
}

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

/* Resolve a host to a single IPv4 address (ICMP here is v4-only for now). */
static pmx_status resolve_v4(const char *host, IPAddr *out_addr, char *text,
                             size_t text_cap) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        return PMX_ERR_DNS;
    }
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    *out_addr = sa->sin_addr.S_un.S_addr;
    if (text != NULL && text_cap > 0) {
        if (inet_ntop(AF_INET, &sa->sin_addr, text, text_cap) == NULL) {
            text[0] = '\0';
        }
    }
    freeaddrinfo(res);
    return PMX_OK;
}

static void reverse_dns(const char *ip, char *out, size_t cap) {
    out[0] = '\0';
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        return;
    }
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, (DWORD)sizeof(host),
                    NULL, 0, NI_NAMEREQD) == 0) {
        pmx_strlcpy(out, host, cap);
    }
}

/* One echo. Returns 1 if a reply structure came back (which includes
 * TTL-exceeded replies from routers), 0 otherwise. */
static int icmp_probe(HANDLE h, IPAddr dest, int ttl, int timeout_ms, int payload,
                      char *addr_out, size_t addr_cap, int *rtt_out,
                      ULONG *status_out) {
    char send_buf[256];
    if (payload < 0) {
        payload = 0;
    }
    if (payload > (int)sizeof(send_buf)) {
        payload = (int)sizeof(send_buf);
    }
    memset(send_buf, 'p', (size_t)payload);

    char reply_buf[1024];
    IP_OPTION_INFORMATION opts;
    memset(&opts, 0, sizeof(opts));
    opts.Ttl = (UCHAR)(ttl > 0 ? ttl : 128);

    DWORD n = IcmpSendEcho(h, dest, send_buf, (WORD)payload, &opts, reply_buf,
                           (DWORD)sizeof(reply_buf), (DWORD)timeout_ms);
    if (n == 0) {
        if (status_out != NULL) {
            *status_out = GetLastError();
        }
        return 0;
    }
    PICMP_ECHO_REPLY r = (PICMP_ECHO_REPLY)reply_buf;
    if (status_out != NULL) {
        *status_out = r->Status;
    }
    if (rtt_out != NULL) {
        *rtt_out = (int)r->RoundTripTime;
    }
    if (addr_out != NULL && addr_cap > 0) {
        struct in_addr ia;
        ia.S_un.S_addr = r->Address;
        if (inet_ntop(AF_INET, &ia, addr_out, addr_cap) == NULL) {
            addr_out[0] = '\0';
        }
    }
    return 1;
}

pmx_status pmx_ping(const char *host, int ttl, int timeout_ms,
                    pmx_ping_result *out) {
    if (host == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->rtt_ms = -1;

    pmx_net_init();
    IPAddr dest = 0;
    pmx_status st = resolve_v4(host, &dest, NULL, 0);
    if (st != PMX_OK) {
        out->status = st;
        pmx_net_shutdown();
        return st;
    }
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        out->status = PMX_ERR_NET;
        pmx_net_shutdown();
        return PMX_ERR_NET;
    }
    ULONG s = 0;
    int rtt = -1;
    int got = icmp_probe(h, dest, ttl, timeout_ms, 32, out->addr,
                         sizeof(out->addr), &rtt, &s);
    IcmpCloseHandle(h);
    pmx_net_shutdown();

    if (got && s == IP_SUCCESS) {
        out->reachable = true;
        out->rtt_ms = rtt;
        out->status = PMX_OK;
        return PMX_OK;
    }
    if (got && s == IP_TTL_EXPIRED_TRANSIT) {
        /* A router answered — useful for traceroute, not "reachable". */
        out->rtt_ms = rtt;
        out->status = PMX_OK;
        return PMX_OK;
    }
    out->status = (s == IP_REQ_TIMED_OUT) ? PMX_ERR_TIMEOUT : PMX_ERR_NET;
    return out->status;
}

/* ---- MTR --------------------------------------------------------------- */

struct pmx_mtr_job {
    char host[PMX_MAX_HOST];
    pmx_path_opts opts;
    pmx_mutex *mutex;
    pmx_thread *thread;
    bool finished;
    bool cancel;
    int progress;
    pmx_mtr_result result;
};

static bool job_cancelled(pmx_mtr_job *job) {
    if (job == NULL) {
        return false;
    }
    pmx_mutex_lock(job->mutex);
    bool c = job->cancel;
    pmx_mutex_unlock(job->mutex);
    return c;
}

static void job_progress(pmx_mtr_job *job, int hop) {
    if (job == NULL) {
        return;
    }
    pmx_mutex_lock(job->mutex);
    job->progress = hop;
    pmx_mutex_unlock(job->mutex);
}

static pmx_status mtr_run(const char *host, const pmx_path_opts *o,
                          pmx_mtr_result *out, pmx_mtr_job *job) {
    pmx_path_opts defaults;
    if (o == NULL) {
        pmx_path_opts_defaults(&defaults);
        o = &defaults;
    }
    memset(out, 0, sizeof(*out));
    pmx_strlcpy(out->target, host, sizeof(out->target));

    pmx_net_init();
    IPAddr dest = 0;
    pmx_status st =
        resolve_v4(host, &dest, out->target_addr, sizeof(out->target_addr));
    if (st != PMX_OK) {
        out->status = st;
        pmx_net_shutdown();
        return st;
    }
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        out->status = PMX_ERR_NET;
        pmx_net_shutdown();
        return PMX_ERR_NET;
    }

    int max_hops = (o->max_hops > 0 && o->max_hops <= PMX_MAX_HOPS) ? o->max_hops
                                                                    : PMX_MAX_HOPS;
    int cycles = (o->cycles > 0) ? o->cycles : 3;

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        if (job_cancelled(job)) {
            break;
        }
        job_progress(job, ttl);

        pmx_hop *hop = &out->hops[out->hop_count];
        memset(hop, 0, sizeof(*hop));
        hop->ttl = ttl;
        hop->best_ms = INT_MAX;
        hop->worst_ms = -1;

        double sum = 0.0;
        bool reached = false;

        for (int c = 0; c < cycles; c++) {
            if (job_cancelled(job)) {
                break;
            }
            ULONG s = 0;
            int rtt = -1;
            char addr[PMX_MAX_IP];
            addr[0] = '\0';
            hop->sent++;
            int got = icmp_probe(h, dest, ttl, o->timeout_ms, o->payload_size,
                                 addr, sizeof(addr), &rtt, &s);
            if (got && (s == IP_SUCCESS || s == IP_TTL_EXPIRED_TRANSIT)) {
                hop->recv++;
                if (hop->addr[0] == '\0' && addr[0] != '\0') {
                    pmx_strlcpy(hop->addr, addr, sizeof(hop->addr));
                }
                if (rtt < hop->best_ms) {
                    hop->best_ms = rtt;
                }
                if (rtt > hop->worst_ms) {
                    hop->worst_ms = rtt;
                }
                sum += (double)rtt;
                if (s == IP_SUCCESS) {
                    reached = true;
                }
            }
        }

        if (hop->recv > 0) {
            hop->avg_ms = sum / (double)hop->recv;
        } else {
            hop->best_ms = -1;
            hop->worst_ms = -1;
        }
        hop->loss_pct = (hop->sent > 0)
                            ? (100.0 * (double)(hop->sent - hop->recv) /
                               (double)hop->sent)
                            : 0.0;
        hop->is_dest = reached;
        if (o->resolve_names && hop->addr[0] != '\0') {
            reverse_dns(hop->addr, hop->name, sizeof(hop->name));
        }
        out->hop_count++;

        if (reached) {
            out->reached = true;
            break;
        }
    }

    IcmpCloseHandle(h);
    pmx_net_shutdown();
    out->status = PMX_OK;
    return PMX_OK;
}

pmx_status pmx_mtr(const char *host, const pmx_path_opts *opts,
                   pmx_mtr_result *out) {
    if (host == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    return mtr_run(host, opts, out, NULL);
}

static void mtr_worker(void *arg) {
    pmx_mtr_job *job = (pmx_mtr_job *)arg;
    pmx_mtr_result r;
    mtr_run(job->host, &job->opts, &r, job);
    pmx_mutex_lock(job->mutex);
    job->result = r;
    job->finished = true;
    pmx_mutex_unlock(job->mutex);
}

pmx_mtr_job *pmx_mtr_start(const char *host, const pmx_path_opts *opts) {
    if (host == NULL) {
        return NULL;
    }
    pmx_mtr_job *job = (pmx_mtr_job *)calloc(1, sizeof(*job));
    if (job == NULL) {
        return NULL;
    }
    pmx_strlcpy(job->host, host, sizeof(job->host));
    if (opts != NULL) {
        job->opts = *opts;
    } else {
        pmx_path_opts_defaults(&job->opts);
    }
    job->mutex = pmx_mutex_create();
    if (job->mutex == NULL) {
        free(job);
        return NULL;
    }
    if (pmx_thread_start(mtr_worker, job, &job->thread) != PMX_OK) {
        pmx_mutex_destroy(job->mutex);
        free(job);
        return NULL;
    }
    return job;
}

bool pmx_mtr_done(pmx_mtr_job *job, pmx_mtr_result *out) {
    if (job == NULL) {
        return false;
    }
    pmx_mutex_lock(job->mutex);
    bool fin = job->finished;
    if (fin && out != NULL) {
        *out = job->result;
    }
    pmx_mutex_unlock(job->mutex);
    return fin;
}

int pmx_mtr_progress(pmx_mtr_job *job) {
    if (job == NULL) {
        return 0;
    }
    pmx_mutex_lock(job->mutex);
    int p = job->progress;
    pmx_mutex_unlock(job->mutex);
    return p;
}

void pmx_mtr_free(pmx_mtr_job *job) {
    if (job == NULL) {
        return;
    }
    pmx_mutex_lock(job->mutex);
    job->cancel = true;
    pmx_mutex_unlock(job->mutex);
    if (job->thread != NULL) {
        pmx_thread_join(job->thread);
    }
    pmx_mutex_destroy(job->mutex);
    free(job);
}

#else /* !_WIN32 — raw ICMP needs root; not wired up yet. */

pmx_status pmx_ping(const char *host, int ttl, int timeout_ms,
                    pmx_ping_result *out) {
    (void)host;
    (void)ttl;
    (void)timeout_ms;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->rtt_ms = -1;
        out->status = PMX_ERR_UNSUPPORTED;
    }
    return PMX_ERR_UNSUPPORTED;
}

pmx_status pmx_mtr(const char *host, const pmx_path_opts *opts,
                   pmx_mtr_result *out) {
    (void)host;
    (void)opts;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->status = PMX_ERR_UNSUPPORTED;
    }
    return PMX_ERR_UNSUPPORTED;
}

pmx_mtr_job *pmx_mtr_start(const char *host, const pmx_path_opts *opts) {
    (void)host;
    (void)opts;
    return NULL;
}
bool pmx_mtr_done(pmx_mtr_job *job, pmx_mtr_result *out) {
    (void)job;
    (void)out;
    return false;
}
int pmx_mtr_progress(pmx_mtr_job *job) {
    (void)job;
    return 0;
}
void pmx_mtr_free(pmx_mtr_job *job) { (void)job; }

#endif
