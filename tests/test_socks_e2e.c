/*
 * test_socks_e2e.c — end-to-end proof that the SOCKS5 client works over a real
 * socket, not just that its encoders produce the right bytes.
 *
 *   test client --[pmx_proxy_handshake SOCKS5]--> SOCKS5 server --> echo server
 *
 * The client negotiates SOCKS5 with the in-test server, asks it to reach the
 * echo server, sends a payload, and must read the same bytes back.
 */
#include "pmx_test.h"
#include "test_servers.h"
#include "proximight/pmx_proxy.h"
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

    pmx_socket cli = PMX_INVALID_SOCKET;
    CHECK(pmx_tcp_connect("127.0.0.1", socks.port, 5000, &cli) == PMX_OK);

    pmx_proxy px;
    pmx_proxy_init(&px);
    px.type = PMX_PROXY_SOCKS5;
    pmx_strlcpy(px.host, "127.0.0.1", sizeof(px.host));
    px.port = socks.port;
    px.use_auth = false;

    CHECK(pmx_proxy_handshake(cli, &px, "127.0.0.1", echo.port, 5000) == PMX_OK);

    const char *msg = "hello proximight";
    size_t n = strlen(msg);
    CHECK(pmx_send_all(cli, msg, n) == PMX_OK);

    char rb[64];
    memset(rb, 0, sizeof(rb));
    CHECK(pmx_recv_exact(cli, rb, n, 5000) == PMX_OK);
    rb[n] = '\0';
    CHECK_STR_EQ(rb, msg);

    pmx_socket_close(cli);
    pmx_thread_join(t_socks);
    pmx_thread_join(t_echo);
    ts_close(&echo);
    ts_close(&socks);
    pmx_net_shutdown();
    return pmx_test_report();
}
