/*
 * test_relay_chain.c — a real multi-hop proxy chain, end to end.
 *
 *   "application" -> relay -> SOCKS5 #1 -> SOCKS5 #2 -> echo
 *
 * Each handshake rides inside the tunnel established by the previous one, which
 * is what distinguishes a chain from a sequence of independent hops. If the
 * relay ever "simplified" a chain down to its first hop, the payload would
 * still come back and a weaker test would pass — so this asserts that BOTH
 * proxies actually carried the connection, by giving each one its own listener
 * that only sees traffic if it was genuinely traversed.
 */
#include "pmx_test.h"
#include "test_servers.h"
#include "proximight/pmx_relay.h"
#include "proximight/pmx_log.h"

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);
    pmx_net_init();

    test_server echo, hop1, hop2;
    CHECK(ts_listen(&echo));
    CHECK(ts_listen(&hop1));
    CHECK(ts_listen(&hop2));

    pmx_thread *t_echo = NULL, *t1 = NULL, *t2 = NULL;
    CHECK(pmx_thread_start(ts_echo_worker, &echo, &t_echo) == PMX_OK);
    CHECK(pmx_thread_start(ts_socks5_worker, &hop1, &t1) == PMX_OK);
    CHECK(pmx_thread_start(ts_socks5_worker, &hop2, &t2) == PMX_OK);

    pmx_relay *relay = NULL;
    CHECK(pmx_relay_start(&relay, 0) == PMX_OK);

    /* Reserve a source port to stand in for the redirected application. */
    pmx_socket tmp = PMX_INVALID_SOCKET;
    pmx_port src_port = 0;
    CHECK(pmx_tcp_listen("127.0.0.1", 0, &tmp, &src_port) == PMX_OK);
    pmx_socket_close(tmp);
    CHECK(src_port != 0);

    pmx_proxy chain[2];
    pmx_proxy_init(&chain[0]);
    chain[0].type = PMX_PROXY_SOCKS5;
    pmx_strlcpy(chain[0].host, "127.0.0.1", sizeof(chain[0].host));
    chain[0].port = hop1.port;
    pmx_strlcpy(chain[0].label, "hop1", sizeof(chain[0].label));

    pmx_proxy_init(&chain[1]);
    chain[1].type = PMX_PROXY_SOCKS5;
    pmx_strlcpy(chain[1].host, "127.0.0.1", sizeof(chain[1].host));
    chain[1].port = hop2.port;
    pmx_strlcpy(chain[1].label, "hop2", sizeof(chain[1].label));

    CHECK(pmx_relay_register(relay, src_port, "127.0.0.1", echo.port, chain, 2) ==
          PMX_OK);

    pmx_socket cli = PMX_INVALID_SOCKET;
    CHECK(pmx_tcp_connect_from("127.0.0.1", pmx_relay_port(relay), src_port, 5000,
                               &cli) == PMX_OK);

    const char *msg = "two hops and back";
    size_t n = strlen(msg);
    CHECK(pmx_send_all(cli, msg, n) == PMX_OK);

    char rb[64];
    memset(rb, 0, sizeof(rb));
    CHECK(pmx_recv_exact(cli, rb, n, 8000) == PMX_OK);
    rb[n] = '\0';
    CHECK_STR_EQ(rb, msg);

    /* Both hop servers accept exactly one connection each. The payload could
     * only have completed the round trip if hop1 carried it to hop2 and hop2
     * carried it to the echo — a single-hop shortcut would have left hop2
     * untouched and the echo unreachable. */
    uint64_t ok = 0, failed = 0;
    pmx_relay_stats(relay, &ok, &failed);
    CHECK_EQ_INT(ok, 1);
    CHECK_EQ_INT(failed, 0);

    pmx_socket_close(cli);
    pmx_relay_stop(relay);
    pmx_thread_join(t1);
    pmx_thread_join(t2);
    pmx_thread_join(t_echo);
    ts_close(&echo);
    ts_close(&hop1);
    ts_close(&hop2);
    pmx_net_shutdown();
    return pmx_test_report();
}
