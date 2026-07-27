/*
 * pmx_proxy.h — a proxy server entry and the client-side handshake that steers
 * a connected socket to a target host:port through it.
 *
 * Supported today: SOCKS4, SOCKS4a, SOCKS5 (+ user/pass auth), HTTP CONNECT.
 * HTTPS proxy (CONNECT over TLS to the proxy) is declared but returns
 * PMX_ERR_UNSUPPORTED until a TLS backend is added — see docs/ROADMAP.md.
 */
#ifndef PROXIMIGHT_PMX_PROXY_H
#define PROXIMIGHT_PMX_PROXY_H

#include "proximight/pmx_net.h"

PMX_BEGIN_DECLS

typedef enum pmx_proxy_type {
    PMX_PROXY_SOCKS5 = 0,
    PMX_PROXY_SOCKS4,
    PMX_PROXY_SOCKS4A,
    PMX_PROXY_HTTP,  /* HTTP CONNECT tunnel                        */
    PMX_PROXY_HTTPS, /* HTTP CONNECT over TLS to the proxy (TODO)  */
    PMX_PROXY_TYPE__COUNT
} pmx_proxy_type;

typedef struct pmx_proxy {
    pmx_id id;
    char label[PMX_MAX_LABEL];
    pmx_proxy_type type;
    char host[PMX_MAX_HOST];
    pmx_port port;
    bool use_auth;
    char username[PMX_MAX_USER];
    char password[PMX_MAX_PASS]; /* never logged */
    bool enabled;
} pmx_proxy;

/* Initialize a proxy to sane defaults (SOCKS5, enabled, port 1080). */
void pmx_proxy_init(pmx_proxy *p);

const char *pmx_proxy_type_str(pmx_proxy_type t);       /* "SOCKS5", ...      */
const char *pmx_proxy_type_short(pmx_proxy_type t);     /* "socks5", ...      */
bool pmx_proxy_type_from_str(const char *s, pmx_proxy_type *out);
pmx_port pmx_proxy_type_default_port(pmx_proxy_type t);

/* Validate user-entered fields. Returns PMX_OK or a specific error; on error,
 * *why (optional) gets a short human message. */
pmx_status pmx_proxy_validate(const pmx_proxy *p, char *why, size_t why_size);

/*
 * Perform the proxy handshake on an already-connected socket `s` so that,
 * afterward, `s` carries a tunnel to (dst_host, dst_port). Blocking, bounded by
 * timeout_ms. Returns PMX_OK or a PMX_ERR_PROXY_* / PMX_ERR_* code.
 */
pmx_status pmx_proxy_handshake(pmx_socket s, const pmx_proxy *p,
                               const char *dst_host, pmx_port dst_port,
                               int timeout_ms);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_PROXY_H */
