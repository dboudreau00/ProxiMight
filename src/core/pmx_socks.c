#include "proximight/pmx_socks.h"

#include <stdio.h> /* sscanf — without this the call below is an implicit
                    * declaration: a constraint violation since C99 that MSVC
                    * only warns about, and calling a variadic function with no
                    * visible prototype is undefined behaviour. clang/gcc reject
                    * it outright, which would break this portable-core file on
                    * the macOS/Linux path. */
#include <string.h>
#include <stdlib.h>

/* Parse a dotted IPv4 literal into 4 octets. Returns false if not a clean IPv4
 * literal (e.g. it's a hostname). Rejects out-of-range and trailing junk. */
static bool parse_ipv4(const char *host, uint8_t out[4]) {
    if (host == NULL) {
        return false;
    }
    unsigned vals[4];
    int consumed = 0;
    /* sscanf with %n to ensure the whole string was the literal. */
    int n = sscanf(host, "%u.%u.%u.%u%n", &vals[0], &vals[1], &vals[2], &vals[3],
                   &consumed);
    if (n != 4 || host[consumed] != '\0') {
        return false;
    }
    for (int i = 0; i < 4; i++) {
        if (vals[i] > 255) {
            return false;
        }
        out[i] = (uint8_t)vals[i];
    }
    return true;
}

static void put_port_be(uint8_t *p, pmx_port port) {
    p[0] = (uint8_t)((port >> 8) & 0xFF);
    p[1] = (uint8_t)(port & 0xFF);
}

/* ------------------------------------------------------------- SOCKS5 --- */

pmx_status pmx_socks5_build_greeting(uint8_t *buf, size_t cap, size_t *out_len,
                                     bool with_auth) {
    if (buf == NULL || out_len == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t need = with_auth ? 4u : 3u;
    if (cap < need) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t i = 0;
    buf[i++] = 0x05; /* VER */
    if (with_auth) {
        buf[i++] = 0x02;       /* NMETHODS */
        buf[i++] = 0x00;       /* NO AUTH  */
        buf[i++] = 0x02;       /* USER/PASS */
    } else {
        buf[i++] = 0x01;       /* NMETHODS */
        buf[i++] = 0x00;       /* NO AUTH  */
    }
    *out_len = i;
    return PMX_OK;
}

pmx_status pmx_socks5_build_userpass(uint8_t *buf, size_t cap, size_t *out_len,
                                     const char *user, const char *pass) {
    if (buf == NULL || out_len == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (user == NULL) {
        user = "";
    }
    if (pass == NULL) {
        pass = "";
    }
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);
    if (ulen > 255 || plen > 255) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t need = 1 + 1 + ulen + 1 + plen;
    if (cap < need) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t i = 0;
    buf[i++] = 0x01; /* auth version */
    buf[i++] = (uint8_t)ulen;
    memcpy(buf + i, user, ulen);
    i += ulen;
    buf[i++] = (uint8_t)plen;
    memcpy(buf + i, pass, plen);
    i += plen;
    *out_len = i;
    return PMX_OK;
}

pmx_status pmx_socks5_build_connect(uint8_t *buf, size_t cap, size_t *out_len,
                                    const char *host, pmx_port port) {
    if (buf == NULL || out_len == NULL || host == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    uint8_t ip4[4];
    size_t i = 0;

    if (parse_ipv4(host, ip4)) {
        if (cap < 4 + 4 + 2) {
            return PMX_ERR_INVALID_ARG;
        }
        buf[i++] = 0x05; /* VER   */
        buf[i++] = 0x01; /* CMD=CONNECT */
        buf[i++] = 0x00; /* RSV   */
        buf[i++] = 0x01; /* ATYP=IPv4 */
        memcpy(buf + i, ip4, 4);
        i += 4;
    } else {
        size_t hlen = strlen(host);
        if (hlen > 255) {
            return PMX_ERR_INVALID_ARG;
        }
        if (cap < 4 + 1 + hlen + 2) {
            return PMX_ERR_INVALID_ARG;
        }
        buf[i++] = 0x05;
        buf[i++] = 0x01;
        buf[i++] = 0x00;
        buf[i++] = 0x03; /* ATYP=DOMAINNAME */
        buf[i++] = (uint8_t)hlen;
        memcpy(buf + i, host, hlen);
        i += hlen;
    }
    put_port_be(buf + i, port);
    i += 2;
    *out_len = i;
    return PMX_OK;
}

pmx_status pmx_socks5_parse_method(const uint8_t *buf, size_t len,
                                   uint8_t *out_method) {
    if (buf == NULL || len < 2) {
        return PMX_ERR_PARSE;
    }
    if (buf[0] != 0x05) {
        return PMX_ERR_PROXY_HANDSHAKE;
    }
    if (out_method != NULL) {
        *out_method = buf[1];
    }
    if (buf[1] == 0xFF) {
        return PMX_ERR_PROXY_AUTH; /* no acceptable methods */
    }
    return PMX_OK;
}

pmx_status pmx_socks5_parse_connect_reply(const uint8_t *buf, size_t len,
                                          uint8_t *out_reply) {
    if (buf == NULL || len < 2) {
        return PMX_ERR_PARSE;
    }
    if (out_reply != NULL) {
        *out_reply = buf[1];
    }
    switch (buf[1]) {
    case 0x00: return PMX_OK;
    case 0x02: return PMX_ERR_PERMISSION;    /* connection not allowed */
    case 0x03: return PMX_ERR_NET;           /* network unreachable    */
    case 0x04: return PMX_ERR_NET;           /* host unreachable       */
    case 0x05: return PMX_ERR_CONN_REFUSED;  /* connection refused     */
    default:   return PMX_ERR_PROXY_REFUSED;
    }
}

/* ------------------------------------------------------------- SOCKS4 --- */

pmx_status pmx_socks4_build_connect(uint8_t *buf, size_t cap, size_t *out_len,
                                    const char *host, pmx_port port,
                                    bool socks4a, const char *userid) {
    if (buf == NULL || out_len == NULL || host == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (userid == NULL) {
        userid = "";
    }
    size_t uidlen = strlen(userid);
    uint8_t ip4[4];
    bool is_ip = parse_ipv4(host, ip4);

    if (!is_ip && !socks4a) {
        /* Plain SOCKS4 cannot carry a hostname. */
        return PMX_ERR_UNSUPPORTED;
    }

    size_t need = 1 + 1 + 2 + 4 + uidlen + 1;
    size_t hlen = 0;
    if (!is_ip) { /* socks4a */
        hlen = strlen(host);
        need += hlen + 1;
    }
    if (cap < need) {
        return PMX_ERR_INVALID_ARG;
    }

    size_t i = 0;
    buf[i++] = 0x04; /* VER */
    buf[i++] = 0x01; /* CD=CONNECT */
    put_port_be(buf + i, port);
    i += 2;
    if (is_ip) {
        memcpy(buf + i, ip4, 4);
        i += 4;
    } else {
        /* 0.0.0.x sentinel signals SOCKS4a hostname mode. */
        buf[i++] = 0x00;
        buf[i++] = 0x00;
        buf[i++] = 0x00;
        buf[i++] = 0x01;
    }
    memcpy(buf + i, userid, uidlen);
    i += uidlen;
    buf[i++] = 0x00; /* userid NUL */
    if (!is_ip) {
        memcpy(buf + i, host, hlen);
        i += hlen;
        buf[i++] = 0x00; /* hostname NUL */
    }
    *out_len = i;
    return PMX_OK;
}

pmx_status pmx_socks4_parse_reply(const uint8_t *buf, size_t len) {
    if (buf == NULL || len < 8) {
        return PMX_ERR_PARSE;
    }
    /* buf[0] is the reply version (0x00). buf[1] is the result code. */
    switch (buf[1]) {
    case 0x5A: return PMX_OK;               /* granted            */
    case 0x5B: return PMX_ERR_PROXY_REFUSED; /* rejected/failed    */
    case 0x5C: return PMX_ERR_PROXY_HANDSHAKE; /* no identd        */
    case 0x5D: return PMX_ERR_PROXY_AUTH;   /* identd mismatch    */
    default:   return PMX_ERR_PROXY_HANDSHAKE;
    }
}
