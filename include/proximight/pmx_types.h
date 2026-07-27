/*
 * pmx_types.h — common fixed-size types, limits, and linkage macros.
 *
 * ProxiMight favors fixed-capacity char buffers over heap strings for the
 * small, bounded strings in its data model (labels, hosts, credentials). This
 * keeps the profile structs flat, trivially copyable, and free of ownership
 * bugs. Genuinely unbounded collections (the lists of proxies/rules/chains)
 * use explicit growable arrays instead.
 */
#ifndef PROXIMIGHT_PMX_TYPES_H
#define PROXIMIGHT_PMX_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#define PMX_BEGIN_DECLS extern "C" {
#define PMX_END_DECLS }
#else
#define PMX_BEGIN_DECLS
#define PMX_END_DECLS
#endif

/* printf-style format checking on GCC/Clang; no-op on MSVC. */
#if defined(__GNUC__) || defined(__clang__)
#define PMX_PRINTF(fmt_idx, va_idx) __attribute__((format(printf, fmt_idx, va_idx)))
#else
#define PMX_PRINTF(fmt_idx, va_idx)
#endif

/* ------------------------------------------------------------------ limits */
#define PMX_MAX_LABEL 64     /* human label for a proxy/chain/profile        */
#define PMX_MAX_NAME 96      /* rule name                                    */
#define PMX_MAX_HOST 256     /* hostname or IP literal                       */
#define PMX_MAX_USER 128     /* proxy username                               */
#define PMX_MAX_PASS 256     /* proxy password (kept out of logs)            */
#define PMX_MAX_PATH 1024    /* filesystem path                              */
#define PMX_MAX_PATTERN 512  /* app/host match pattern (';'-separated globs) */
#define PMX_MAX_PORTSPEC 128 /* port spec, e.g. "80,443,8000-8080"           */
#define PMX_MAX_MSG 192      /* short status/result message                  */
#define PMX_MAX_IP 64        /* textual IP (v4/v6)                           */
#define PMX_MAX_CHAIN_HOPS 8 /* proxies per chain                            */

typedef uint16_t pmx_port;
typedef uint64_t pmx_id; /* stable object id; 0 == PMX_ID_NONE == invalid    */

#define PMX_ID_NONE ((pmx_id)0)

/* Number of elements in a fixed C array. */
#define PMX_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Safe bounded string copy: always NUL-terminates, never overflows `dst`. */
static inline void pmx_strlcpy(char *dst, const char *src, size_t dst_size) {
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    for (; i + 1 < dst_size && src[i] != '\0'; ++i) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

#endif /* PROXIMIGHT_PMX_TYPES_H */
