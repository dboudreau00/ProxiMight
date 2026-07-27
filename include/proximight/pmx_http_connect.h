/*
 * pmx_http_connect.h — HTTP CONNECT request builder + reply parser.
 *
 * Pure functions, unit-testable without I/O. Used by pmx_proxy_handshake() for
 * PMX_PROXY_HTTP (and, once TLS lands, PMX_PROXY_HTTPS).
 */
#ifndef PROXIMIGHT_PMX_HTTP_CONNECT_H
#define PROXIMIGHT_PMX_HTTP_CONNECT_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

/*
 * Build a "CONNECT host:port HTTP/1.1" request into `buf`. If user/pass are
 * non-empty, adds a Proxy-Authorization: Basic header. Writes a NUL-terminated
 * string and sets *out_len to its byte length (excluding the NUL).
 */
pmx_status pmx_http_build_connect(char *buf, size_t cap, size_t *out_len,
                                  const char *host, pmx_port port,
                                  const char *user, const char *pass);

/*
 * Parse the status line of a CONNECT reply. `buf` holds `len` received bytes
 * (need at least the status line). *out_code gets the numeric HTTP status.
 * Returns PMX_OK on 2xx, PMX_ERR_PROXY_AUTH on 407, else PMX_ERR_PROXY_REFUSED.
 * Returns PMX_ERR_PARSE if the status line is not yet complete/valid.
 */
pmx_status pmx_http_parse_connect_reply(const char *buf, size_t len,
                                        int *out_code);

/* Standard Base64 of `in` into `out` (NUL-terminated). Exposed for auth headers
 * and unit tests. */
pmx_status pmx_base64_encode(const uint8_t *in, size_t in_len, char *out,
                             size_t out_cap, size_t *out_len);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_HTTP_CONNECT_H */
