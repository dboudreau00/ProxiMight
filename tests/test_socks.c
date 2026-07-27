#include "pmx_test.h"
#include "proximight/pmx_socks.h"
#include "proximight/pmx_http_connect.h"

#include <string.h>

int main(void) {
    uint8_t buf[64];
    size_t len = 0;

    /* SOCKS5 greeting, no auth. */
    CHECK(pmx_socks5_build_greeting(buf, sizeof(buf), &len, false) == PMX_OK);
    CHECK_EQ_INT(len, 3);
    CHECK_EQ_INT(buf[0], 0x05);
    CHECK_EQ_INT(buf[1], 0x01);
    CHECK_EQ_INT(buf[2], 0x00);

    /* SOCKS5 greeting, with auth. */
    CHECK(pmx_socks5_build_greeting(buf, sizeof(buf), &len, true) == PMX_OK);
    CHECK_EQ_INT(len, 4);
    CHECK_EQ_INT(buf[1], 0x02);
    CHECK_EQ_INT(buf[3], 0x02);

    /* SOCKS5 CONNECT to an IPv4 literal. */
    CHECK(pmx_socks5_build_connect(buf, sizeof(buf), &len, "1.2.3.4", 80) == PMX_OK);
    CHECK_EQ_INT(len, 10);
    CHECK_EQ_INT(buf[3], 0x01); /* ATYP IPv4 */
    CHECK_EQ_INT(buf[4], 1);
    CHECK_EQ_INT(buf[7], 4);
    CHECK_EQ_INT(buf[8], 0x00); /* port hi */
    CHECK_EQ_INT(buf[9], 0x50); /* port lo = 80 */

    /* SOCKS5 CONNECT to a hostname. */
    CHECK(pmx_socks5_build_connect(buf, sizeof(buf), &len, "example.com", 443) ==
          PMX_OK);
    CHECK_EQ_INT(buf[3], 0x03);          /* DOMAINNAME */
    CHECK_EQ_INT(buf[4], 11);            /* len("example.com") */
    CHECK_EQ_INT(len, 4 + 1 + 11 + 2);
    CHECK_EQ_INT(buf[len - 2], 0x01);    /* 443 hi */
    CHECK_EQ_INT(buf[len - 1], 0xBB);    /* 443 lo */

    /* SOCKS5 user/pass. */
    CHECK(pmx_socks5_build_userpass(buf, sizeof(buf), &len, "u", "pw") == PMX_OK);
    CHECK_EQ_INT(len, 1 + 1 + 1 + 1 + 2);
    CHECK_EQ_INT(buf[0], 0x01);
    CHECK_EQ_INT(buf[1], 1);
    CHECK_EQ_INT(buf[2], 'u');
    CHECK_EQ_INT(buf[3], 2);

    /* SOCKS5 reply parsing. */
    uint8_t okrep[4] = {0x05, 0x00, 0x00, 0x01};
    uint8_t reprep[4] = {0x05, 0x05, 0x00, 0x01};
    uint8_t r = 0;
    CHECK(pmx_socks5_parse_connect_reply(okrep, 4, &r) == PMX_OK);
    CHECK(pmx_socks5_parse_connect_reply(reprep, 4, &r) == PMX_ERR_CONN_REFUSED);

    /* SOCKS4 CONNECT (IPv4). */
    CHECK(pmx_socks4_build_connect(buf, sizeof(buf), &len, "1.2.3.4", 80, false,
                                   "") == PMX_OK);
    CHECK_EQ_INT(len, 9);
    CHECK_EQ_INT(buf[0], 0x04);
    CHECK_EQ_INT(buf[1], 0x01);
    CHECK_EQ_INT(buf[8], 0x00); /* userid NUL */

    /* Plain SOCKS4 cannot carry a hostname. */
    CHECK(pmx_socks4_build_connect(buf, sizeof(buf), &len, "example.com", 80, false,
                                   "") == PMX_ERR_UNSUPPORTED);

    /* SOCKS4a CONNECT (hostname). */
    CHECK(pmx_socks4_build_connect(buf, sizeof(buf), &len, "example.com", 80, true,
                                   "me") == PMX_OK);
    CHECK_EQ_INT(buf[4], 0x00);
    CHECK_EQ_INT(buf[5], 0x00);
    CHECK_EQ_INT(buf[6], 0x00);
    CHECK_EQ_INT(buf[7], 0x01);           /* 0.0.0.1 sentinel */
    CHECK_EQ_INT(buf[len - 1], 0x00);     /* trailing hostname NUL */

    /* SOCKS4 reply. */
    uint8_t s4ok[8] = {0x00, 0x5A, 0, 0, 0, 0, 0, 0};
    uint8_t s4rej[8] = {0x00, 0x5B, 0, 0, 0, 0, 0, 0};
    CHECK(pmx_socks4_parse_reply(s4ok, 8) == PMX_OK);
    CHECK(pmx_socks4_parse_reply(s4rej, 8) == PMX_ERR_PROXY_REFUSED);

    /* Base64. */
    char b64[16];
    size_t bl = 0;
    CHECK(pmx_base64_encode((const uint8_t *)"Man", 3, b64, sizeof(b64), &bl) ==
          PMX_OK);
    CHECK_STR_EQ(b64, "TWFu");
    CHECK(pmx_base64_encode((const uint8_t *)"M", 1, b64, sizeof(b64), &bl) ==
          PMX_OK);
    CHECK_STR_EQ(b64, "TQ==");

    /* HTTP CONNECT reply parsing. */
    int code = 0;
    const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
    const char *auth = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
    CHECK(pmx_http_parse_connect_reply(ok, strlen(ok), &code) == PMX_OK);
    CHECK_EQ_INT(code, 200);
    CHECK(pmx_http_parse_connect_reply(auth, strlen(auth), &code) ==
          PMX_ERR_PROXY_AUTH);
    CHECK_EQ_INT(code, 407);

    /* HTTP CONNECT request builder. */
    char req[256];
    size_t rl = 0;
    CHECK(pmx_http_build_connect(req, sizeof(req), &rl, "example.com", 443, NULL,
                                 NULL) == PMX_OK);
    CHECK(strstr(req, "CONNECT example.com:443 HTTP/1.1") == req);
    CHECK(strstr(req, "Host: example.com:443") != NULL);

    return pmx_test_report();
}
