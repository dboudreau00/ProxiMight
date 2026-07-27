/*
 * pmx_socks.h — SOCKS4/4a/5 message encoders and reply parsers.
 *
 * These are pure, side-effect-free byte builders/parsers so they can be unit
 * tested without a network (see tests/test_socks.c). pmx_proxy_handshake() uses
 * them and adds the socket I/O.
 */
#ifndef PROXIMIGHT_PMX_SOCKS_H
#define PROXIMIGHT_PMX_SOCKS_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

/* --- SOCKS5 (RFC 1928 / 1929) ------------------------------------------- */

/* Method-selection greeting. If with_auth, offers both NO_AUTH (0x00) and
 * USERNAME/PASSWORD (0x02); otherwise only NO_AUTH. */
pmx_status pmx_socks5_build_greeting(uint8_t *buf, size_t cap, size_t *out_len,
                                     bool with_auth);

/* Username/password auth sub-negotiation request (RFC 1929). */
pmx_status pmx_socks5_build_userpass(uint8_t *buf, size_t cap, size_t *out_len,
                                     const char *user, const char *pass);

/* CONNECT request to host:port. Encodes host as IPv4/IPv6 literal when it is
 * one, else as a DOMAINNAME (proxy resolves it). */
pmx_status pmx_socks5_build_connect(uint8_t *buf, size_t cap, size_t *out_len,
                                    const char *host, pmx_port port);

/* Parse the 2-byte method-selection reply; *out_method is the chosen method. */
pmx_status pmx_socks5_parse_method(const uint8_t *buf, size_t len,
                                   uint8_t *out_method);

/* Parse a CONNECT reply header. Returns PMX_OK if REP==0x00 (granted), else a
 * mapped error. *out_reply carries the raw REP byte for diagnostics. */
pmx_status pmx_socks5_parse_connect_reply(const uint8_t *buf, size_t len,
                                          uint8_t *out_reply);

/* --- SOCKS4 / 4a -------------------------------------------------------- */

/* CONNECT request. If socks4a, host is sent as a name (0.0.0.x sentinel +
 * trailing hostname); otherwise host must be an IPv4 literal. userid may be
 * NULL/empty. */
pmx_status pmx_socks4_build_connect(uint8_t *buf, size_t cap, size_t *out_len,
                                    const char *host, pmx_port port,
                                    bool socks4a, const char *userid);

/* Parse the 8-byte SOCKS4 reply; PMX_OK iff CD==0x5A (granted). */
pmx_status pmx_socks4_parse_reply(const uint8_t *buf, size_t len);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_SOCKS_H */
