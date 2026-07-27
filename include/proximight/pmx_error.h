/*
 * pmx_error.h — status codes returned throughout the core.
 *
 * Convention: functions return pmx_status; PMX_OK (0) is success, everything
 * else is a specific failure. Never smuggle secrets into a message string.
 */
#ifndef PROXIMIGHT_PMX_ERROR_H
#define PROXIMIGHT_PMX_ERROR_H

#include "proximight/pmx_types.h"

PMX_BEGIN_DECLS

typedef enum pmx_status {
    PMX_OK = 0,

    PMX_ERR_INVALID_ARG,   /* caller passed a bad argument                  */
    PMX_ERR_NO_MEMORY,     /* allocation failed                             */
    PMX_ERR_STATE,         /* operation invalid in the current state        */
    PMX_ERR_UNSUPPORTED,   /* not implemented / not available on this build */
    PMX_ERR_NOT_FOUND,     /* id/name/file not found                        */
    PMX_ERR_EXISTS,        /* would duplicate something unique              */

    PMX_ERR_IO,            /* file read/write failed                        */
    PMX_ERR_PARSE,         /* malformed profile / protocol data             */
    PMX_ERR_CRYPTO,        /* seal/unseal failed (bad key/user/machine/tag) */

    PMX_ERR_NET,           /* generic socket/network error                  */
    PMX_ERR_TIMEOUT,       /* operation timed out                           */
    PMX_ERR_CONN_REFUSED,  /* TCP connect refused                           */
    PMX_ERR_DNS,           /* name resolution failed                        */

    PMX_ERR_PROXY_HANDSHAKE, /* proxy spoke, but negotiation failed         */
    PMX_ERR_PROXY_AUTH,      /* proxy rejected credentials                  */
    PMX_ERR_PROXY_REFUSED,   /* proxy refused to reach the target           */

    PMX_ERR_BACKEND,       /* redirection backend failed                    */
    PMX_ERR_FIREWALL,      /* firewall/lockdown enforcement failed          */
    PMX_ERR_PERMISSION,    /* needs admin/root or an entitlement            */

    PMX_STATUS__COUNT
} pmx_status;

/* Stable, human-readable, secret-free description of a status code. */
const char *pmx_status_str(pmx_status status);

/* True for any non-OK code. */
static inline bool pmx_failed(pmx_status s) { return s != PMX_OK; }

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_ERROR_H */
