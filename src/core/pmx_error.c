#include "proximight/pmx_error.h"

const char *pmx_status_str(pmx_status status) {
    switch (status) {
    case PMX_OK:                 return "OK";
    case PMX_ERR_INVALID_ARG:    return "invalid argument";
    case PMX_ERR_NO_MEMORY:      return "out of memory";
    case PMX_ERR_STATE:          return "invalid state";
    case PMX_ERR_UNSUPPORTED:    return "unsupported";
    case PMX_ERR_NOT_FOUND:      return "not found";
    case PMX_ERR_EXISTS:         return "already exists";
    case PMX_ERR_IO:             return "I/O error";
    case PMX_ERR_PARSE:          return "parse error";
    case PMX_ERR_CRYPTO:         return "encryption/decryption failed";
    case PMX_ERR_NET:            return "network error";
    case PMX_ERR_TIMEOUT:        return "timed out";
    case PMX_ERR_CONN_REFUSED:   return "connection refused";
    case PMX_ERR_DNS:            return "DNS resolution failed";
    case PMX_ERR_PROXY_HANDSHAKE:return "proxy handshake failed";
    case PMX_ERR_PROXY_AUTH:     return "proxy authentication failed";
    case PMX_ERR_PROXY_REFUSED:  return "proxy refused the target";
    case PMX_ERR_BACKEND:        return "backend error";
    case PMX_ERR_FIREWALL:       return "firewall error";
    case PMX_ERR_PERMISSION:     return "insufficient privilege";
    case PMX_STATUS__COUNT:      break;
    }
    return "unknown error";
}
