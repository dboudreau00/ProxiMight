#include "proximight/pmx_proxy.h"
#include "proximight/pmx_socks.h"
#include "proximight/pmx_http_connect.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdio.h>

void pmx_proxy_init(pmx_proxy *p) {
    if (p == NULL) {
        return;
    }
    memset(p, 0, sizeof(*p));
    p->type = PMX_PROXY_SOCKS5;
    p->port = 1080;
    p->enabled = true;
    pmx_strlcpy(p->label, "New proxy", sizeof(p->label));
}

const char *pmx_proxy_type_str(pmx_proxy_type t) {
    switch (t) {
    case PMX_PROXY_SOCKS5:  return "SOCKS5";
    case PMX_PROXY_SOCKS4:  return "SOCKS4";
    case PMX_PROXY_SOCKS4A: return "SOCKS4a";
    case PMX_PROXY_HTTP:    return "HTTP";
    case PMX_PROXY_HTTPS:   return "HTTPS";
    case PMX_PROXY_TYPE__COUNT: break;
    }
    return "?";
}

const char *pmx_proxy_type_short(pmx_proxy_type t) {
    switch (t) {
    case PMX_PROXY_SOCKS5:  return "socks5";
    case PMX_PROXY_SOCKS4:  return "socks4";
    case PMX_PROXY_SOCKS4A: return "socks4a";
    case PMX_PROXY_HTTP:    return "http";
    case PMX_PROXY_HTTPS:   return "https";
    case PMX_PROXY_TYPE__COUNT: break;
    }
    return "?";
}

bool pmx_proxy_type_from_str(const char *s, pmx_proxy_type *out) {
    if (s == NULL || out == NULL) {
        return false;
    }
    for (int t = 0; t < PMX_PROXY_TYPE__COUNT; t++) {
#if defined(_WIN32)
        if (_stricmp(s, pmx_proxy_type_short((pmx_proxy_type)t)) == 0)
#else
        if (strcasecmp(s, pmx_proxy_type_short((pmx_proxy_type)t)) == 0)
#endif
        {
            *out = (pmx_proxy_type)t;
            return true;
        }
    }
    return false;
}

pmx_port pmx_proxy_type_default_port(pmx_proxy_type t) {
    switch (t) {
    case PMX_PROXY_SOCKS5:
    case PMX_PROXY_SOCKS4:
    case PMX_PROXY_SOCKS4A: return 1080;
    case PMX_PROXY_HTTP:    return 8080;
    case PMX_PROXY_HTTPS:   return 8443;
    default:                return 1080;
    }
}

pmx_status pmx_proxy_validate(const pmx_proxy *p, char *why, size_t why_size) {
#define FAIL(code, text)                                                        \
    do {                                                                        \
        if (why != NULL)                                                        \
            pmx_strlcpy(why, (text), why_size);                                 \
        return (code);                                                          \
    } while (0)

    if (p == NULL) {
        FAIL(PMX_ERR_INVALID_ARG, "null proxy");
    }
    if (p->host[0] == '\0') {
        FAIL(PMX_ERR_INVALID_ARG, "host is required");
    }
    if (p->port == 0) {
        FAIL(PMX_ERR_INVALID_ARG, "port must be 1-65535");
    }
    if (p->type < 0 || p->type >= PMX_PROXY_TYPE__COUNT) {
        FAIL(PMX_ERR_INVALID_ARG, "unknown proxy type");
    }
    if (p->use_auth && p->username[0] == '\0') {
        FAIL(PMX_ERR_INVALID_ARG, "username required when auth is on");
    }
    if (p->type == PMX_PROXY_HTTPS) {
        FAIL(PMX_ERR_UNSUPPORTED, "HTTPS proxy (TLS) not implemented yet");
    }
    if (why != NULL && why_size > 0) {
        why[0] = '\0';
    }
    return PMX_OK;
#undef FAIL
}

/* ---- handshake helpers ------------------------------------------------- */

static pmx_status socks5_handshake(pmx_socket s, const pmx_proxy *p,
                                   const char *host, pmx_port port, int tmo) {
    uint8_t buf[512];
    size_t len = 0;
    pmx_status st;

    st = pmx_socks5_build_greeting(buf, sizeof(buf), &len, p->use_auth);
    if (st != PMX_OK) return st;
    st = pmx_send_all(s, buf, len);
    if (st != PMX_OK) return st;

    uint8_t reply[2];
    st = pmx_recv_exact(s, reply, 2, tmo);
    if (st != PMX_OK) return st;
    uint8_t method = 0;
    st = pmx_socks5_parse_method(reply, 2, &method);
    if (st != PMX_OK) return st;

    if (method == 0x02) {
        st = pmx_socks5_build_userpass(buf, sizeof(buf), &len, p->username,
                                       p->password);
        if (st != PMX_OK) return st;
        st = pmx_send_all(s, buf, len);
        if (st != PMX_OK) return st;
        uint8_t ar[2];
        st = pmx_recv_exact(s, ar, 2, tmo);
        if (st != PMX_OK) return st;
        if (ar[1] != 0x00) {
            return PMX_ERR_PROXY_AUTH;
        }
    } else if (method != 0x00) {
        return PMX_ERR_PROXY_AUTH;
    }

    st = pmx_socks5_build_connect(buf, sizeof(buf), &len, host, port);
    if (st != PMX_OK) return st;
    st = pmx_send_all(s, buf, len);
    if (st != PMX_OK) return st;

    /* Reply header: VER REP RSV ATYP, then a bound address + 2-byte port. */
    uint8_t head[4];
    st = pmx_recv_exact(s, head, 4, tmo);
    if (st != PMX_OK) return st;
    uint8_t rep = 0;
    st = pmx_socks5_parse_connect_reply(head, 4, &rep);
    if (st != PMX_OK) return st;

    size_t addr_len = 0;
    switch (head[3]) {
    case 0x01: addr_len = 4; break;
    case 0x04: addr_len = 16; break;
    case 0x03: {
        uint8_t l = 0;
        st = pmx_recv_exact(s, &l, 1, tmo);
        if (st != PMX_OK) return st;
        addr_len = l;
        break;
    }
    default: return PMX_ERR_PROXY_HANDSHAKE;
    }
    uint8_t drain[256 + 2];
    st = pmx_recv_exact(s, drain, addr_len + 2, tmo);
    if (st != PMX_OK) return st;
    return PMX_OK;
}

static pmx_status socks4_handshake(pmx_socket s, const pmx_proxy *p,
                                   const char *host, pmx_port port, int tmo) {
    uint8_t buf[512];
    size_t len = 0;
    bool socks4a = (p->type == PMX_PROXY_SOCKS4A);
    const char *userid = p->use_auth ? p->username : "";
    pmx_status st =
        pmx_socks4_build_connect(buf, sizeof(buf), &len, host, port, socks4a, userid);
    if (st != PMX_OK) return st;
    st = pmx_send_all(s, buf, len);
    if (st != PMX_OK) return st;
    uint8_t reply[8];
    st = pmx_recv_exact(s, reply, 8, tmo);
    if (st != PMX_OK) return st;
    return pmx_socks4_parse_reply(reply, 8);
}

static pmx_status http_handshake(pmx_socket s, const pmx_proxy *p,
                                 const char *host, pmx_port port, int tmo) {
    char req[1024];
    size_t len = 0;
    const char *user = p->use_auth ? p->username : NULL;
    const char *pass = p->use_auth ? p->password : NULL;
    pmx_status st =
        pmx_http_build_connect(req, sizeof(req), &len, host, port, user, pass);
    if (st != PMX_OK) return st;
    st = pmx_send_all(s, req, len);
    if (st != PMX_OK) return st;

    /* Accumulate until we can read the status line (or hit the end of headers). */
    char resp[1024];
    size_t total = 0;
    for (int attempt = 0; attempt < 8; attempt++) {
        size_t got = 0;
        st = pmx_recv_some(s, resp + total, sizeof(resp) - 1 - total, &got, tmo);
        if (st != PMX_OK) {
            return st;
        }
        total += got;
        resp[total] = '\0';
        int code = 0;
        pmx_status pr = pmx_http_parse_connect_reply(resp, total, &code);
        if (pr != PMX_ERR_PARSE) {
            return pr; /* PMX_OK, auth, or refused */
        }
        if (total >= sizeof(resp) - 1) {
            break;
        }
    }
    return PMX_ERR_PROXY_HANDSHAKE;
}

pmx_status pmx_proxy_handshake(pmx_socket s, const pmx_proxy *p,
                               const char *dst_host, pmx_port dst_port,
                               int timeout_ms) {
    if (p == NULL || dst_host == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    switch (p->type) {
    case PMX_PROXY_SOCKS5:  return socks5_handshake(s, p, dst_host, dst_port, timeout_ms);
    case PMX_PROXY_SOCKS4:
    case PMX_PROXY_SOCKS4A: return socks4_handshake(s, p, dst_host, dst_port, timeout_ms);
    case PMX_PROXY_HTTP:    return http_handshake(s, p, dst_host, dst_port, timeout_ms);
    case PMX_PROXY_HTTPS:   return PMX_ERR_UNSUPPORTED;
    default:                return PMX_ERR_INVALID_ARG;
    }
}
