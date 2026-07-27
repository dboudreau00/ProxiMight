/*
 * test_relay.c — end-to-end proof that the SOCKSifier relay carries traffic.
 *
 *   "application"  --> relay  --> SOCKS5 server --> echo server
 *   (bound to a known source port, exactly like a redirected connection)
 *
 * This exercises the whole proxied path without needing any driver: we play the
 * part of the redirect layer by registering the intended destination for a
 * source port, then connecting from that port.
 */
#include "pmx_test.h"
#include "test_servers.h"
#include "proximight/pmx_relay.h"
#include "proximight/pmx_log.h"

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);
    pmx_net_init();

    test_server echo, socks;
    CHECK(ts_listen(&echo));
    CHECK(ts_listen(&socks));

    pmx_thread *t_echo = NULL, *t_socks = NULL;
    CHECK(pmx_thread_start(ts_echo_worker, &echo, &t_echo) == PMX_OK);
    CHECK(pmx_thread_start(ts_socks5_worker, &socks, &t_socks) == PMX_OK);

    pmx_relay *relay = NULL;
    CHECK(pmx_relay_start(&relay, 0) == PMX_OK);
    CHECK(pmx_relay_port(relay) != 0);

    /* Reserve a free port to act as the application's source port. */
    pmx_socket tmp = PMX_INVALID_SOCKET;
    pmx_port src_port = 0;
    CHECK(pmx_tcp_listen("127.0.0.1", 0, &tmp, &src_port) == PMX_OK);
    pmx_socket_close(tmp);
    CHECK(src_port != 0);

    /* What the redirect layer does just before it NATs the SYN. */
    pmx_proxy via;
    pmx_proxy_init(&via);
    via.type = PMX_PROXY_SOCKS5;
    pmx_strlcpy(via.host, "127.0.0.1", sizeof(via.host));
    via.port = socks.port;
    pmx_strlcpy(via.label, "test socks", sizeof(via.label));
    CHECK(pmx_relay_register(relay, src_port, "127.0.0.1", echo.port, &via, 1) ==
          PMX_OK);
    /* A zero-length chain is meaningless and must be refused, not treated as
     * "go direct". */
    CHECK(pmx_relay_register(relay, 40000, "127.0.0.1", echo.port, &via, 0) ==
          PMX_ERR_INVALID_ARG);

    /* The "application" connects to the relay from that source port. */
    pmx_socket cli = PMX_INVALID_SOCKET;
    CHECK(pmx_tcp_connect_from("127.0.0.1", pmx_relay_port(relay), src_port, 5000,
                               &cli) == PMX_OK);

    const char *msg = "relayed through a proxy";
    size_t n = strlen(msg);
    CHECK(pmx_send_all(cli, msg, n) == PMX_OK);

    char rb[64];
    memset(rb, 0, sizeof(rb));
    CHECK(pmx_recv_exact(cli, rb, n, 8000) == PMX_OK);
    rb[n] = '\0';
    CHECK_STR_EQ(rb, msg);

    uint64_t ok = 0, failed = 0;
    pmx_relay_stats(relay, &ok, &failed);
    CHECK_EQ_INT(ok, 1);
    CHECK_EQ_INT(failed, 0);

    /* A connection with no registration must be dropped, never forwarded
     * blindly — otherwise the relay would be an open proxy. */
    pmx_socket stray = PMX_INVALID_SOCKET;
    if (pmx_tcp_connect("127.0.0.1", pmx_relay_port(relay), 3000, &stray) ==
        PMX_OK) {
        char junk[8];
        size_t got = 0;
        pmx_recv_some(stray, junk, sizeof(junk), &got, 1500); /* expect close */
        pmx_socket_close(stray);
    }
    pmx_sleep_ms(300);
    pmx_relay_stats(relay, &ok, &failed);
    CHECK_EQ_INT(ok, 1);
    CHECK(failed >= 1);

    pmx_socket_close(cli);
    pmx_relay_stop(relay);
    pmx_thread_join(t_socks);
    pmx_thread_join(t_echo);
    ts_close(&echo);
    ts_close(&socks);
    pmx_net_shutdown();
    return pmx_test_report();
}
