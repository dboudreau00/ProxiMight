#include "proximight/pmx_net.h"

#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int pmx_socklen;
#define SOCKET_CAST SOCKET
#define PMX_SOCK_ERR SOCKET_ERROR
#define pmx_closesocket closesocket
static int pmx_last_err(void) { return WSAGetLastError(); }
#define PMX_EWOULDBLOCK WSAEWOULDBLOCK
#define PMX_EINPROGRESS WSAEWOULDBLOCK
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
typedef socklen_t pmx_socklen;
#define SOCKET_CAST int
#define PMX_SOCK_ERR (-1)
#define pmx_closesocket close
static int pmx_last_err(void) { return errno; }
#define PMX_EWOULDBLOCK EWOULDBLOCK
#define PMX_EINPROGRESS EINPROGRESS
#endif

/* ------------------------------------------------------------------- init */
#if defined(_WIN32)
/* Interlocked, NOT a plain int: init/shutdown are called from the GUI thread,
 * both checker workers, the MTR worker and the relay. A non-atomic ++/-- loses
 * updates under that concurrency, and an undercount eventually takes the
 * refcount to 0 while sockets are still open — WSACleanup() then deallocates
 * EVERY socket in the process (relay listener plus every live proxied
 * connection) and subsequent calls fail with WSANOTINITIALISED. Taking the
 * 0->1 and 1->0 edges from the interlocked result makes them exact. */
static volatile LONG g_wsa_refs = 0;
#endif

pmx_status pmx_net_init(void) {
#if defined(_WIN32)
    if (InterlockedIncrement(&g_wsa_refs) == 1) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            InterlockedDecrement(&g_wsa_refs);
            return PMX_ERR_NET;
        }
    }
#endif
    return PMX_OK;
}

void pmx_net_shutdown(void) {
#if defined(_WIN32)
    LONG refs = InterlockedDecrement(&g_wsa_refs);
    if (refs == 0) {
        WSACleanup();
    } else if (refs < 0) {
        /* Unbalanced shutdown: clamp at zero rather than letting the count go
         * negative (which would make a later 0->1 edge skip WSAStartup). */
        InterlockedIncrement(&g_wsa_refs);
    }
#endif
}

/* -------------------------------------------------------------- utilities */
static void set_nonblocking(pmx_socket s, bool on) {
#if defined(_WIN32)
    u_long mode = on ? 1 : 0;
    ioctlsocket((SOCKET)s, FIONBIO, &mode);
#else
    int flags = fcntl((int)s, F_GETFL, 0);
    if (flags < 0) {
        return;
    }
    fcntl((int)s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
}

/* Wait until the socket is readable/writable, or timeout. */
static pmx_status wait_ready(pmx_socket s, bool for_write, int timeout_ms) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET((SOCKET_CAST)s, &set);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int n;
    if (for_write) {
        n = select((int)s + 1, NULL, &set, NULL, &tv);
    } else {
        n = select((int)s + 1, &set, NULL, NULL, &tv);
    }
    if (n == 0) {
        return PMX_ERR_TIMEOUT;
    }
    if (n < 0) {
        return PMX_ERR_NET;
    }
    return PMX_OK;
}

pmx_status pmx_tcp_connect(const char *host, pmx_port port, int timeout_ms,
                           pmx_socket *out) {
    return pmx_tcp_connect_from(host, port, 0, timeout_ms, out);
}

pmx_status pmx_tcp_connect_from(const char *host, pmx_port port,
                                pmx_port local_port, int timeout_ms,
                                pmx_socket *out) {
    if (host == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = PMX_INVALID_SOCKET;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        return PMX_ERR_DNS;
    }

    pmx_status result = PMX_ERR_NET;
    /* `timeout_ms` is a TOTAL budget across every resolved address, as the
     * header promises — not per candidate. A name behind a round-robin pool can
     * return a dozen A/AAAA records; spending the full timeout on each turned a
     * nominal 5 s connect into a minute, which is what made checker stalls (and
     * the shutdown freeze) so long. */
    uint64_t connect_start = pmx_now_ms();
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int remaining = timeout_ms;
        if (timeout_ms > 0) {
            uint64_t elapsed = pmx_now_ms() - connect_start;
            if (elapsed >= (uint64_t)timeout_ms) {
                if (result == PMX_ERR_NET) {
                    result = PMX_ERR_TIMEOUT;
                }
                break;
            }
            remaining = (int)((uint64_t)timeout_ms - elapsed);
        }
        pmx_socket s =
            (pmx_socket)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == PMX_INVALID_SOCKET) {
            continue;
        }
        if (local_port != 0 && ai->ai_family == AF_INET) {
            struct sockaddr_in la;
            memset(&la, 0, sizeof(la));
            la.sin_family = AF_INET;
            la.sin_addr.s_addr = htonl(INADDR_ANY);
            la.sin_port = htons(local_port);
            if (bind((SOCKET_CAST)s, (struct sockaddr *)&la, (pmx_socklen)sizeof(la)) !=
                0) {
                pmx_closesocket((SOCKET_CAST)s);
                result = PMX_ERR_NET;
                continue;
            }
        }
        set_nonblocking(s, true);

        int rc = connect((SOCKET_CAST)s, ai->ai_addr, (pmx_socklen)ai->ai_addrlen);
        if (rc == 0) {
            set_nonblocking(s, false);
            *out = s;
            result = PMX_OK;
            break;
        }
        int err = pmx_last_err();
        if (err == PMX_EINPROGRESS || err == PMX_EWOULDBLOCK) {
            pmx_status w = wait_ready(s, true, remaining);
            if (w == PMX_OK) {
                int soerr = 0;
                pmx_socklen len = sizeof(soerr);
                getsockopt((SOCKET_CAST)s, SOL_SOCKET, SO_ERROR, (char *)&soerr,
                           &len);
                if (soerr == 0) {
                    set_nonblocking(s, false);
                    *out = s;
                    result = PMX_OK;
                    break;
                }
                result = PMX_ERR_CONN_REFUSED;
            } else {
                result = w; /* timeout or net error */
            }
        }
        pmx_closesocket((SOCKET_CAST)s);
    }

    freeaddrinfo(res);
    return result;
}

pmx_status pmx_send_all(pmx_socket s, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n = send((SOCKET_CAST)s, p + sent, (int)(len - sent), 0);
        if (n == PMX_SOCK_ERR || n <= 0) {
            return PMX_ERR_NET;
        }
        sent += (size_t)n;
    }
    return PMX_OK;
}

pmx_status pmx_recv_exact(pmx_socket s, void *buf, size_t len, int timeout_ms) {
    char *p = (char *)buf;
    size_t got = 0;
    /* `timeout_ms` bounds the WHOLE read, not each recv(). Re-arming it per
     * iteration made the total scale with the number of bytes: a peer that
     * dribbles one byte just under the limit could stretch a nominal 5 s read
     * into tens of minutes, pinning the single checker worker — and because the
     * lockdown state machine only advances on a COMPLETED health probe, a
     * hostile proxy could stall the kill switch instead of tripping it. */
    uint64_t start = pmx_now_ms();
    while (got < len) {
        int remaining = timeout_ms;
        if (timeout_ms > 0) {
            uint64_t elapsed = pmx_now_ms() - start;
            if (elapsed >= (uint64_t)timeout_ms) {
                return PMX_ERR_TIMEOUT;
            }
            remaining = (int)((uint64_t)timeout_ms - elapsed);
        }
        pmx_status w = wait_ready(s, false, remaining);
        if (w != PMX_OK) {
            return w;
        }
        int n = recv((SOCKET_CAST)s, p + got, (int)(len - got), 0);
        if (n == 0) {
            return PMX_ERR_NET; /* peer closed */
        }
        if (n == PMX_SOCK_ERR || n < 0) {
            return PMX_ERR_NET;
        }
        got += (size_t)n;
    }
    return PMX_OK;
}

pmx_status pmx_recv_some(pmx_socket s, void *buf, size_t cap, size_t *received,
                         int timeout_ms) {
    if (received != NULL) {
        *received = 0;
    }
    pmx_status w = wait_ready(s, false, timeout_ms);
    if (w != PMX_OK) {
        return w;
    }
    int n = recv((SOCKET_CAST)s, (char *)buf, (int)cap, 0);
    if (n == 0) {
        return PMX_ERR_NET;
    }
    if (n == PMX_SOCK_ERR || n < 0) {
        return PMX_ERR_NET;
    }
    if (received != NULL) {
        *received = (size_t)n;
    }
    return PMX_OK;
}

pmx_status pmx_tcp_listen(const char *bind_host, pmx_port port, pmx_socket *out,
                          pmx_port *actual_port) {
    if (out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = PMX_INVALID_SOCKET;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    const char *host = (bind_host != NULL && bind_host[0] != '\0') ? bind_host
                                                                   : "127.0.0.1";
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        return PMX_ERR_DNS;
    }

    pmx_socket s = (pmx_socket)socket(res->ai_family, res->ai_socktype,
                                      res->ai_protocol);
    if (s == PMX_INVALID_SOCKET) {
        freeaddrinfo(res);
        return PMX_ERR_NET;
    }
    if (bind((SOCKET_CAST)s, res->ai_addr, (pmx_socklen)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        pmx_closesocket((SOCKET_CAST)s);
        return PMX_ERR_NET;
    }
    freeaddrinfo(res);

    if (listen((SOCKET_CAST)s, 16) != 0) {
        pmx_closesocket((SOCKET_CAST)s);
        return PMX_ERR_NET;
    }
    if (actual_port != NULL) {
        struct sockaddr_in a;
        pmx_socklen al = (pmx_socklen)sizeof(a);
        memset(&a, 0, sizeof(a));
        if (getsockname((SOCKET_CAST)s, (struct sockaddr *)&a, &al) == 0) {
            *actual_port = (pmx_port)ntohs(a.sin_port);
        } else {
            *actual_port = port;
        }
    }
    *out = s;
    return PMX_OK;
}

pmx_status pmx_tcp_accept(pmx_socket listener, pmx_socket *out,
                          pmx_port *peer_port) {
    if (out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    struct sockaddr_in a;
    pmx_socklen al = (pmx_socklen)sizeof(a);
    memset(&a, 0, sizeof(a));
    pmx_socket c =
        (pmx_socket)accept((SOCKET_CAST)listener, (struct sockaddr *)&a, &al);
    if (c == PMX_INVALID_SOCKET) {
        return PMX_ERR_NET;
    }
    if (peer_port != NULL) {
        *peer_port = (pmx_port)ntohs(a.sin_port);
    }
    *out = c;
    return PMX_OK;
}

int pmx_wait_two(pmx_socket a, pmx_socket b, int timeout_ms) {
    fd_set r;
    FD_ZERO(&r);
    FD_SET((SOCKET_CAST)a, &r);
    FD_SET((SOCKET_CAST)b, &r);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int nfds = (int)((a > b ? a : b) + 1);
    int n = select(nfds, &r, NULL, NULL, &tv);
    if (n == 0) {
        return 0;
    }
    if (n < 0) {
        return -1;
    }
    int mask = 0;
    if (FD_ISSET((SOCKET_CAST)a, &r)) {
        mask |= 1;
    }
    if (FD_ISSET((SOCKET_CAST)b, &r)) {
        mask |= 2;
    }
    return mask;
}

void pmx_socket_close(pmx_socket s) {
    if (s != PMX_INVALID_SOCKET) {
        pmx_closesocket((SOCKET_CAST)s);
    }
}

/* ---------------------------------------------------------------- clocks */
uint64_t pmx_now_ms(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int have_freq = 0;
    if (!have_freq) {
        QueryPerformanceFrequency(&freq);
        have_freq = 1;
    }
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

void pmx_sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}
