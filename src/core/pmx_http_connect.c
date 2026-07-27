#include "proximight/pmx_http_connect.h"

#include <string.h>
#include <stdio.h>

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pmx_status pmx_base64_encode(const uint8_t *in, size_t in_len, char *out,
                             size_t out_cap, size_t *out_len) {
    if (out == NULL || (in == NULL && in_len > 0)) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t need = ((in_len + 2) / 3) * 4;
    if (out_cap < need + 1) {
        return PMX_ERR_INVALID_ARG;
    }
    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = B64[(n >> 18) & 0x3F];
        out[o++] = B64[(n >> 12) & 0x3F];
        out[o++] = B64[(n >> 6) & 0x3F];
        out[o++] = B64[n & 0x3F];
        i += 3;
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t n = (uint32_t)in[i] << 16;
        out[o++] = B64[(n >> 18) & 0x3F];
        out[o++] = B64[(n >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = B64[(n >> 18) & 0x3F];
        out[o++] = B64[(n >> 12) & 0x3F];
        out[o++] = B64[(n >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    if (out_len != NULL) {
        *out_len = o;
    }
    return PMX_OK;
}

pmx_status pmx_http_build_connect(char *buf, size_t cap, size_t *out_len,
                                  const char *host, pmx_port port,
                                  const char *user, const char *pass) {
    if (buf == NULL || host == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    char auth_header[512];
    auth_header[0] = '\0';

    if (user != NULL && user[0] != '\0') {
        /* "user:pass" -> base64 -> Proxy-Authorization: Basic <b64> */
        char creds[PMX_MAX_USER + PMX_MAX_PASS + 2];
        int cn = snprintf(creds, sizeof(creds), "%s:%s", user,
                          pass != NULL ? pass : "");
        if (cn < 0 || (size_t)cn >= sizeof(creds)) {
            return PMX_ERR_INVALID_ARG;
        }
        char b64[((PMX_MAX_USER + PMX_MAX_PASS + 2 + 2) / 3) * 4 + 4];
        pmx_status s = pmx_base64_encode((const uint8_t *)creds, (size_t)cn, b64,
                                         sizeof(b64), NULL);
        if (s != PMX_OK) {
            return s;
        }
        snprintf(auth_header, sizeof(auth_header),
                 "Proxy-Authorization: Basic %s\r\n", b64);
    }

    int n = snprintf(buf, cap,
                     "CONNECT %s:%u HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "Proxy-Connection: keep-alive\r\n"
                     "%s"
                     "\r\n",
                     host, (unsigned)port, host, (unsigned)port, auth_header);
    if (n < 0 || (size_t)n >= cap) {
        return PMX_ERR_INVALID_ARG;
    }
    if (out_len != NULL) {
        *out_len = (size_t)n;
    }
    return PMX_OK;
}

pmx_status pmx_http_parse_connect_reply(const char *buf, size_t len,
                                        int *out_code) {
    if (buf == NULL || len < 12) {
        return PMX_ERR_PARSE; /* need at least "HTTP/1.x NNN" */
    }
    if (strncmp(buf, "HTTP/", 5) != 0) {
        return PMX_ERR_PARSE;
    }
    /* Find the first space, then parse the 3-digit status. */
    size_t i = 0;
    while (i < len && buf[i] != ' ') {
        i++;
    }
    if (i + 4 > len) {
        return PMX_ERR_PARSE;
    }
    i++; /* skip the space */
    int code = 0;
    int digits = 0;
    while (i < len && buf[i] >= '0' && buf[i] <= '9' && digits < 3) {
        code = code * 10 + (buf[i] - '0');
        i++;
        digits++;
    }
    if (digits != 3) {
        return PMX_ERR_PARSE;
    }
    if (out_code != NULL) {
        *out_code = code;
    }
    if (code >= 200 && code < 300) {
        return PMX_OK;
    }
    if (code == 407) {
        return PMX_ERR_PROXY_AUTH;
    }
    return PMX_ERR_PROXY_REFUSED;
}
