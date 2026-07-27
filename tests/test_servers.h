/*
 * test_servers.h — tiny loopback servers shared by the integration tests.
 *
 * Portable (built on pmx_net), so the same harness works on any platform:
 *   - ts_echo_worker   : echoes everything back until the peer closes
 *   - ts_socks5_worker : a minimal no-auth SOCKS5 CONNECT server that splices
 *
 * Each worker handles exactly one connection, which is all the tests need.
 */
#ifndef PMX_TEST_SERVERS_H
#define PMX_TEST_SERVERS_H

#include "proximight/pmx_net.h"
#include "proximight/pmx_thread.h"

#include <string.h>
#include <stdio.h>

#define TS_TIMEOUT_MS 15000

typedef struct test_server {
    pmx_socket lis;
    pmx_port port;
} test_server;

static int ts_listen(test_server *s) {
    s->lis = PMX_INVALID_SOCKET;
    s->port = 0;
    return pmx_tcp_listen("127.0.0.1", 0, &s->lis, &s->port) == PMX_OK;
}

static void ts_close(test_server *s) {
    if (s != NULL && s->lis != PMX_INVALID_SOCKET) {
        pmx_socket_close(s->lis);
        s->lis = PMX_INVALID_SOCKET;
    }
}

static void ts_splice(pmx_socket a, pmx_socket b) {
    char buf[2048];
    for (;;) {
        int m = pmx_wait_two(a, b, TS_TIMEOUT_MS);
        if (m <= 0) {
            break;
        }
        size_t got = 0;
        if (m & 1) {
            if (pmx_recv_some(a, buf, sizeof(buf), &got, TS_TIMEOUT_MS) != PMX_OK) {
                break;
            }
            if (pmx_send_all(b, buf, got) != PMX_OK) {
                break;
            }
        }
        if (m & 2) {
            if (pmx_recv_some(b, buf, sizeof(buf), &got, TS_TIMEOUT_MS) != PMX_OK) {
                break;
            }
            if (pmx_send_all(a, buf, got) != PMX_OK) {
                break;
            }
        }
    }
}

static void ts_echo_worker(void *arg) {
    test_server *s = (test_server *)arg;
    pmx_socket c = PMX_INVALID_SOCKET;
    if (pmx_tcp_accept(s->lis, &c, NULL) != PMX_OK) {
        return;
    }
    char buf[1024];
    for (;;) {
        size_t got = 0;
        if (pmx_recv_some(c, buf, sizeof(buf), &got, TS_TIMEOUT_MS) != PMX_OK) {
            break;
        }
        if (pmx_send_all(c, buf, got) != PMX_OK) {
            break;
        }
    }
    pmx_socket_close(c);
}

static void ts_socks5_worker(void *arg) {
    test_server *s = (test_server *)arg;
    pmx_socket c = PMX_INVALID_SOCKET;
    if (pmx_tcp_accept(s->lis, &c, NULL) != PMX_OK) {
        return;
    }
    unsigned char b[300];

    /* greeting -> "no auth" */
    if (pmx_recv_exact(c, b, 2, TS_TIMEOUT_MS) != PMX_OK || b[0] != 0x05) {
        pmx_socket_close(c);
        return;
    }
    size_t nmethods = b[1];
    if (nmethods > 0 &&
        pmx_recv_exact(c, b, nmethods, TS_TIMEOUT_MS) != PMX_OK) {
        pmx_socket_close(c);
        return;
    }
    unsigned char method_reply[2] = {0x05, 0x00};
    if (pmx_send_all(c, method_reply, 2) != PMX_OK) {
        pmx_socket_close(c);
        return;
    }

    /* CONNECT request */
    if (pmx_recv_exact(c, b, 4, TS_TIMEOUT_MS) != PMX_OK || b[1] != 0x01) {
        pmx_socket_close(c);
        return;
    }
    char host[256];
    host[0] = '\0';
    if (b[3] == 0x01) {
        unsigned char ip[4];
        if (pmx_recv_exact(c, ip, 4, TS_TIMEOUT_MS) != PMX_OK) {
            pmx_socket_close(c);
            return;
        }
        snprintf(host, sizeof(host), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    } else if (b[3] == 0x03) {
        unsigned char l = 0;
        if (pmx_recv_exact(c, &l, 1, TS_TIMEOUT_MS) != PMX_OK ||
            pmx_recv_exact(c, host, l, TS_TIMEOUT_MS) != PMX_OK) {
            pmx_socket_close(c);
            return;
        }
        host[l] = '\0';
    } else {
        pmx_socket_close(c);
        return;
    }
    unsigned char pb[2];
    if (pmx_recv_exact(c, pb, 2, TS_TIMEOUT_MS) != PMX_OK) {
        pmx_socket_close(c);
        return;
    }
    pmx_port port = (pmx_port)(((unsigned)pb[0] << 8) | (unsigned)pb[1]);

    pmx_socket t = PMX_INVALID_SOCKET;
    pmx_status st = pmx_tcp_connect(host, port, TS_TIMEOUT_MS, &t);
    unsigned char rep[10] = {0x05, (unsigned char)(st == PMX_OK ? 0x00 : 0x01),
                             0x00, 0x01, 0, 0, 0, 0, 0, 0};
    pmx_send_all(c, rep, 10);
    if (st != PMX_OK) {
        pmx_socket_close(c);
        return;
    }

    ts_splice(c, t);
    pmx_socket_close(t);
    pmx_socket_close(c);
}

#endif /* PMX_TEST_SERVERS_H */
