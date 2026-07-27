#include "proximight/pmx_vpn.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/* ------------------------------------------------------------- helpers --- */

static void trim(char *s) {
    if (s == NULL) {
        return;
    }
    char *p = s;
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
}

static bool ci_eq(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

/* Strip a trailing comment ('#' always; ';' only for INI-style configs). */
static void strip_comment(char *s, bool semicolon_too) {
    for (char *p = s; *p != '\0'; p++) {
        if (*p == '#' || (semicolon_too && *p == ';')) {
            *p = '\0';
            return;
        }
    }
}

/* In-place whitespace tokenizer. Returns the token count. */
static size_t tokenize(char *line, char **tok, size_t max) {
    size_t n = 0;
    char *p = line;
    while (*p != '\0' && n < max) {
        while (*p != '\0' && isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        tok[n++] = p;
        while (*p != '\0' && !isspace((unsigned char)*p)) {
            p++;
        }
        if (*p != '\0') {
            *p++ = '\0';
        }
    }
    return n;
}

/* "host:port" or "[v6::addr]:port". */
static bool parse_hostport(const char *s, char *host, size_t hcap,
                           pmx_port *port) {
    if (s == NULL || host == NULL || port == NULL) {
        return false;
    }
    if (*s == '[') {
        const char *end = strchr(s, ']');
        if (end == NULL || *(end + 1) != ':') {
            return false;
        }
        size_t n = (size_t)(end - s - 1);
        if (n >= hcap) {
            n = hcap - 1;
        }
        memcpy(host, s + 1, n);
        host[n] = '\0';
        long p = strtol(end + 2, NULL, 10);
        *port = (pmx_port)p;
        return p > 0 && p <= 65535;
    }
    const char *colon = strrchr(s, ':');
    if (colon == NULL) {
        return false;
    }
    size_t n = (size_t)(colon - s);
    if (n == 0) {
        return false;
    }
    if (n >= hcap) {
        n = hcap - 1;
    }
    memcpy(host, s, n);
    host[n] = '\0';
    long p = strtol(colon + 1, NULL, 10);
    *port = (pmx_port)p;
    return p > 0 && p <= 65535;
}

static void add_endpoint(pmx_vpn *v, const char *host, pmx_port port, bool udp) {
    if (host == NULL || host[0] == '\0') {
        return;
    }
    if (v->endpoint_count >= PMX_MAX_VPN_ENDPOINTS) {
        /* Commercial .ovpn files routinely list 10-20 failover remotes. A
         * dropped one is not cosmetic: lockdown allowlists these endpoints, so
         * if the client rotates to a remote we never recorded, the kill switch
         * blocks the tunnel's own handshake. Record it so the UI can say so. */
        v->endpoints_truncated = true;
        return;
    }
    pmx_vpn_endpoint *e = &v->endpoints[v->endpoint_count++];
    memset(e, 0, sizeof(*e));
    pmx_strlcpy(e->host, host, sizeof(e->host));
    e->port = port;
    e->udp = udp;
}

/* Editors on Windows love to save configs as UTF-8 *with BOM*. Those three
 * bytes are otherwise invisible and would glue themselves to the first token:
 * "\xEF\xBB\xBF[Interface]" never matches "[Interface]", so the whole section
 * was skipped and the file was rejected with a confusing "no PrivateKey". */
static const char *skip_bom(const char *text) {
    if (text != NULL && (unsigned char)text[0] == 0xEF &&
        (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
        return text + 3;
    }
    return text;
}

/* Does this AllowedIPs value route *everything*? Besides the obvious 0.0.0.0/0
 * and ::/0, the two-halves idiom (0.0.0.0/1 + 128.0.0.0/1, and ::/1 + 8000::/1)
 * also covers the whole address space — it is what many providers emit to beat
 * a default route on metric. Calling that "split tunnel" in the UI would be an
 * inverted privacy claim, which is worse than saying nothing. */
static bool allowed_ips_is_full_tunnel(const char *val) {
    if (val == NULL) {
        return false;
    }
    if (strstr(val, "0.0.0.0/0") != NULL || strstr(val, "::/0") != NULL) {
        return true;
    }
    if (strstr(val, "0.0.0.0/1") != NULL && strstr(val, "128.0.0.0/1") != NULL) {
        return true;
    }
    if (strstr(val, "::/1") != NULL && strstr(val, "8000::/1") != NULL) {
        return true;
    }
    return false;
}

/* ---------------------------------------------------------------- api ---- */

void pmx_vpn_init(pmx_vpn *v) {
    if (v == NULL) {
        return;
    }
    memset(v, 0, sizeof(*v));
    v->kind = PMX_VPN_WIREGUARD;
    v->enabled = true;
    pmx_strlcpy(v->label, "New VPN", sizeof(v->label));
}

const char *pmx_vpn_kind_str(pmx_vpn_kind k) {
    switch (k) {
    case PMX_VPN_WIREGUARD: return "WireGuard";
    case PMX_VPN_OPENVPN:   return "OpenVPN";
    case PMX_VPN_KIND__COUNT: break;
    }
    return "?";
}

pmx_status pmx_vpn_sniff(const char *text, pmx_vpn_kind *out_kind) {
    if (text == NULL || out_kind == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    text = skip_bom(text);
    /* WireGuard configs are INI with an [Interface] section. */
    if (strstr(text, "[Interface]") != NULL || strstr(text, "[interface]") != NULL) {
        *out_kind = PMX_VPN_WIREGUARD;
        return PMX_OK;
    }
    /* OpenVPN is directive based. */
    if (strstr(text, "remote ") != NULL || strstr(text, "\nclient") != NULL ||
        strncmp(text, "client", 6) == 0 || strstr(text, "dev tun") != NULL ||
        strstr(text, "dev tap") != NULL || strstr(text, "proto ") != NULL) {
        *out_kind = PMX_VPN_OPENVPN;
        return PMX_OK;
    }
    return PMX_ERR_PARSE;
}

/* --------------------------------------------------------- WireGuard ----- */

pmx_status pmx_vpn_parse_wireguard(const char *text, pmx_vpn *out) {
    if (text == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_vpn_init(out);
    out->kind = PMX_VPN_WIREGUARD;

    enum { SEC_NONE, SEC_IFACE, SEC_PEER } sec = SEC_NONE;
    const char *p = skip_bom(text);
    char line[1024];

    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) {
            len = sizeof(line) - 1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        p = nl ? nl + 1 : p + strlen(p);

        strip_comment(line, true);
        trim(line);
        if (line[0] == '\0') {
            continue;
        }

        if (line[0] == '[') {
            if (ci_eq(line, "[Interface]")) {
                sec = SEC_IFACE;
            } else if (ci_eq(line, "[Peer]")) {
                sec = SEC_PEER;
            } else {
                sec = SEC_NONE;
            }
            continue;
        }

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);
        if (key[0] == '\0') {
            continue;
        }

        if (sec == SEC_IFACE) {
            if (ci_eq(key, "PrivateKey")) {
                out->has_private_key = true; /* presence only — never stored */
            } else if (ci_eq(key, "Address")) {
                pmx_strlcpy(out->address, val, sizeof(out->address));
            } else if (ci_eq(key, "DNS")) {
                pmx_strlcpy(out->dns, val, sizeof(out->dns));
            } else if (ci_eq(key, "MTU")) {
                out->mtu = (int)strtol(val, NULL, 10);
            }
        } else if (sec == SEC_PEER) {
            if (ci_eq(key, "PublicKey")) {
                pmx_strlcpy(out->peer_public_key, val,
                            sizeof(out->peer_public_key));
            } else if (ci_eq(key, "PresharedKey")) {
                out->has_preshared_key = true; /* presence only */
            } else if (ci_eq(key, "AllowedIPs")) {
                pmx_strlcpy(out->allowed_ips, val, sizeof(out->allowed_ips));
                if (allowed_ips_is_full_tunnel(val)) {
                    out->full_tunnel = true;
                }
            } else if (ci_eq(key, "Endpoint")) {
                char host[PMX_MAX_HOST];
                pmx_port port = 0;
                if (parse_hostport(val, host, sizeof(host), &port)) {
                    add_endpoint(out, host, port, true); /* WG is always UDP */
                }
            } else if (ci_eq(key, "PersistentKeepalive")) {
                out->persistent_keepalive = (int)strtol(val, NULL, 10);
            }
        }
    }

    if (out->endpoint_count == 0) {
        return PMX_ERR_PARSE;
    }
    return PMX_OK;
}

/* ----------------------------------------------------------- OpenVPN ----- */

/* Inline blocks holding private material. Their contents are skipped and only
 * their presence is recorded. */
static bool is_secret_tag(const char *tag) {
    static const char *const secrets[] = {"key",    "tls-auth",   "tls-crypt",
                                          "tls-crypt-v2", "secret", "pkcs12"};
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++) {
        if (ci_eq(tag, secrets[i])) {
            return true;
        }
    }
    return false;
}

/* OpenVPN treats ANY <tag> … </tag> as an inline *file* whose body is data, not
 * configuration. We must do the same, and default to skipping.
 *
 * This used to allowlist ten known tags (ca/cert/dh/key/tls-auth/…) and parse
 * the body of everything else as directives — so a config could hide
 * `remote evil.example.com 443` inside a block we didn't recognize
 * (<auth-user-pass>, <crl-verify>, <peer-fingerprint>, <http-proxy-user-pass>, …)
 * and have it added as a tunnel endpoint. pmx_engine copies every parsed
 * endpoint into the lockdown ALLOWLIST, so that punched an attacker-chosen hole
 * straight through the kill switch — the exact config-injection this parser
 * exists to prevent. The old test only passed because it used <ca>.
 *
 * `<connection>` is the one deliberate exception: its body really is
 * configuration, and OpenVPN parses it as such. */
static bool is_parsed_container_tag(const char *tag) {
    /* Case-SENSITIVE, for the same reason the closing tag is: OpenVPN matches
     * option names case-sensitively, so it treats <Connection> as an
     * unrecognized inline FILE and never reads its body as configuration. A
     * case-insensitive match here would parse a block OpenVPN ignores — letting
     * `remote evil.example.com` inside <Connection> become a real endpoint (and
     * hence a kill-switch allowlist entry), which is the exact injection the
     * skip-everything default exists to prevent. Only lowercase is parsed. */
    return strcmp(tag, "connection") == 0;
}

pmx_status pmx_vpn_parse_openvpn(const char *text, pmx_vpn *out) {
    if (text == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    pmx_vpn_init(out);
    out->kind = PMX_VPN_OPENVPN;

    bool default_udp = true;
    pmx_port default_port = 1194;
    char skipping_tag[64];
    skipping_tag[0] = '\0';

    const char *p = skip_bom(text);
    char line[1024];

    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) {
            len = sizeof(line) - 1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        p = nl ? nl + 1 : p + strlen(p);
        trim(line);

        /* Inside a skipped inline block: look only for its closing tag so that
         * base64 payloads are never interpreted as directives. */
        if (skipping_tag[0] != '\0') {
            if (line[0] == '<' && line[1] == '/') {
                char close_tag[64];
                pmx_strlcpy(close_tag, line + 2, sizeof(close_tag));
                char *gt = strchr(close_tag, '>');
                if (gt != NULL) {
                    *gt = '\0';
                }
                /* Case-SENSITIVE, like OpenVPN: if we ended <ca> on a stray
                 * </CA>, we would resume parsing at a point OpenVPN still
                 * considers certificate data — and a `remote` line placed
                 * there would be injected. Not matching just keeps skipping,
                 * which fails closed. */
                if (strcmp(close_tag, skipping_tag) == 0) {
                    skipping_tag[0] = '\0';
                }
            }
            continue;
        }

        if (line[0] == '<' && line[1] != '/') {
            char tag[64];
            pmx_strlcpy(tag, line + 1, sizeof(tag));
            char *gt = strchr(tag, '>');
            if (gt != NULL) {
                *gt = '\0';
            }
            /* Skip EVERY inline block by default; only <connection> is parsed. */
            if (!is_parsed_container_tag(tag)) {
                if (is_secret_tag(tag)) {
                    out->has_inline_secrets = true;
                }
                pmx_strlcpy(skipping_tag, tag, sizeof(skipping_tag));
            }
            continue;
        }
        if (line[0] == '<' && line[1] == '/') {
            continue; /* stray close of a container we parsed inline */
        }

        strip_comment(line, true);
        trim(line);
        if (line[0] == '\0') {
            continue;
        }

        char *tok[8];
        size_t n = tokenize(line, tok, 8);
        if (n == 0) {
            continue;
        }

        if (ci_eq(tok[0], "remote") && n >= 2) {
            pmx_port port = (n >= 3) ? (pmx_port)strtol(tok[2], NULL, 10) : 0;
            bool udp = default_udp;
            if (n >= 4) {
                udp = !(ci_eq(tok[3], "tcp") || ci_eq(tok[3], "tcp-client") ||
                        ci_eq(tok[3], "tcp4") || ci_eq(tok[3], "tcp6"));
            }
            add_endpoint(out, tok[1], port, udp);
        } else if (ci_eq(tok[0], "proto") && n >= 2) {
            default_udp = !(ci_eq(tok[1], "tcp") || ci_eq(tok[1], "tcp-client") ||
                            ci_eq(tok[1], "tcp4") || ci_eq(tok[1], "tcp6"));
        } else if (ci_eq(tok[0], "port") && n >= 2) {
            default_port = (pmx_port)strtol(tok[1], NULL, 10);
        } else if ((ci_eq(tok[0], "cipher") || ci_eq(tok[0], "data-ciphers")) &&
                   n >= 2) {
            if (out->cipher[0] == '\0') {
                pmx_strlcpy(out->cipher, tok[1], sizeof(out->cipher));
            }
        } else if (ci_eq(tok[0], "auth") && n >= 2) {
            pmx_strlcpy(out->auth_digest, tok[1], sizeof(out->auth_digest));
        } else if (ci_eq(tok[0], "dev") && n >= 2) {
            pmx_strlcpy(out->dev, tok[1], sizeof(out->dev));
        } else if (ci_eq(tok[0], "auth-user-pass")) {
            out->requires_user_pass = true;
        } else if (ci_eq(tok[0], "redirect-gateway")) {
            out->full_tunnel = true;
        } else if (ci_eq(tok[0], "tun-mtu") && n >= 2) {
            out->mtu = (int)strtol(tok[1], NULL, 10);
        } else if (ci_eq(tok[0], "dhcp-option") && n >= 3 &&
                   ci_eq(tok[1], "DNS")) {
            pmx_strlcpy(out->dns, tok[2], sizeof(out->dns));
        }
    }

    /* Apply the global proto/port to remotes that didn't specify one. */
    for (size_t i = 0; i < out->endpoint_count; i++) {
        if (out->endpoints[i].port == 0) {
            out->endpoints[i].port = default_port ? default_port : 1194;
        }
    }

    if (out->endpoint_count == 0) {
        return PMX_ERR_PARSE;
    }
    return PMX_OK;
}

/* ------------------------------------------------------------- loading --- */

static pmx_status read_all(const char *path, char **out) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return PMX_ERR_IO;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return PMX_ERR_IO;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return PMX_ERR_NO_MEMORY;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    return PMX_OK;
}

static void basename_of(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    const char *base = path;
    if (slash != NULL && slash + 1 > base) {
        base = slash + 1;
    }
    if (bslash != NULL && bslash + 1 > base) {
        base = bslash + 1;
    }
    pmx_strlcpy(out, base, cap);
    char *dot = strrchr(out, '.');
    if (dot != NULL && dot != out) {
        *dot = '\0';
    }
}

pmx_status pmx_vpn_load_file(const char *path, pmx_vpn *out) {
    if (path == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    char *text = NULL;
    pmx_status st = read_all(path, &text);
    if (st != PMX_OK) {
        return st;
    }

    pmx_vpn_kind kind;
    st = pmx_vpn_sniff(text, &kind);
    if (st != PMX_OK) {
        free(text);
        return st;
    }
    st = (kind == PMX_VPN_WIREGUARD) ? pmx_vpn_parse_wireguard(text, out)
                                     : pmx_vpn_parse_openvpn(text, out);
    free(text);
    if (st != PMX_OK) {
        return st;
    }

    pmx_strlcpy(out->config_path, path, sizeof(out->config_path));
    basename_of(path, out->label, sizeof(out->label));
    if (out->label[0] == '\0') {
        pmx_strlcpy(out->label, pmx_vpn_kind_str(out->kind), sizeof(out->label));
    }
    /* Deliberately logs the endpoint COUNT but never the config body. */
    PMX_LOGI("Imported %s VPN '%s' (%zu endpoint(s))",
             pmx_vpn_kind_str(out->kind), out->label, out->endpoint_count);
    if (out->endpoints_truncated) {
        /* Not cosmetic: lockdown allowlists exactly these endpoints, so a
         * remote we dropped is one the tunnel can never reach once the kill
         * switch is armed — the client rotates to it and the handshake is
         * blocked, with nothing otherwise explaining why. */
        PMX_LOGW("VPN '%s' lists more remotes than ProxiMight tracks (%d); the "
                 "extra ones are NOT in the kill-switch allowlist, so if the "
                 "client fails over to one the tunnel will be blocked.",
                 out->label, PMX_MAX_VPN_ENDPOINTS);
    }
    return PMX_OK;
}

/* ------------------------------------------------- vendor client lookup --- */

static bool file_exists(const char *p) {
    if (p == NULL || p[0] == '\0') {
        return false;
    }
    FILE *f = fopen(p, "rb");
    if (f != NULL) {
        fclose(f);
        return true;
    }
    return false;
}

pmx_status pmx_vpn_client_detect(pmx_vpn_kind kind, const char *override_path,
                                 pmx_vpn_client *out) {
    if (out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    if (file_exists(override_path)) {
        out->found = true;
        pmx_strlcpy(out->path, override_path, sizeof(out->path));
        return PMX_OK;
    }

    static const char *const wg_paths[] = {
        "C:\\Program Files\\WireGuard\\wireguard.exe",
        "C:\\Program Files (x86)\\WireGuard\\wireguard.exe",
        "/usr/bin/wg-quick",
        "/usr/local/bin/wg-quick",
        "/opt/homebrew/bin/wg-quick",
    };
    static const char *const ovpn_paths[] = {
        "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
        "C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe",
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
        "/opt/homebrew/sbin/openvpn",
    };

    const char *const *list = (kind == PMX_VPN_WIREGUARD) ? wg_paths : ovpn_paths;
    size_t n = (kind == PMX_VPN_WIREGUARD)
                   ? sizeof(wg_paths) / sizeof(wg_paths[0])
                   : sizeof(ovpn_paths) / sizeof(ovpn_paths[0]);

    for (size_t i = 0; i < n; i++) {
        if (file_exists(list[i])) {
            out->found = true;
            pmx_strlcpy(out->path, list[i], sizeof(out->path));
            return PMX_OK;
        }
    }
    return PMX_ERR_NOT_FOUND;
}

pmx_status pmx_vpn_bringup_command(const pmx_vpn *v, const pmx_vpn_client *client,
                                   char *out, size_t cap) {
    if (v == NULL || out == NULL || cap == 0) {
        return PMX_ERR_INVALID_ARG;
    }
    out[0] = '\0';
    const char *exe = (client != NULL && client->found) ? client->path
                                                        : "<vpn client>";
    if (v->config_path[0] == '\0') {
        return PMX_ERR_INVALID_ARG;
    }
    if (v->kind == PMX_VPN_WIREGUARD) {
        snprintf(out, cap, "\"%s\" /installtunnelservice \"%s\"", exe,
                 v->config_path);
    } else {
        /* --management gives a control socket to monitor/stop the tunnel. */
        snprintf(out, cap, "\"%s\" --config \"%s\" --management 127.0.0.1 %u",
                 exe, v->config_path, 25340u);
    }
    return PMX_OK;
}

pmx_status pmx_vpn_validate(const pmx_vpn *v, char *why, size_t why_size) {
#define VFAIL(code, text)                                                       \
    do {                                                                        \
        if (why != NULL)                                                        \
            pmx_strlcpy(why, (text), why_size);                                 \
        return (code);                                                          \
    } while (0)

    if (v == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (v->endpoint_count == 0) {
        VFAIL(PMX_ERR_INVALID_ARG, "no remote endpoint in the config");
    }
    for (size_t i = 0; i < v->endpoint_count; i++) {
        if (v->endpoints[i].host[0] == '\0' || v->endpoints[i].port == 0) {
            VFAIL(PMX_ERR_INVALID_ARG, "an endpoint is missing a host or port");
        }
    }
    if (v->kind == PMX_VPN_WIREGUARD) {
        if (v->peer_public_key[0] == '\0') {
            VFAIL(PMX_ERR_INVALID_ARG, "WireGuard peer has no PublicKey");
        }
        if (!v->has_private_key) {
            VFAIL(PMX_ERR_INVALID_ARG,
                  "WireGuard [Interface] has no PrivateKey");
        }
    }
    if (v->config_path[0] == '\0') {
        VFAIL(PMX_ERR_INVALID_ARG,
              "no config file path — the VPN client needs the original file");
    }
    if (why != NULL && why_size > 0) {
        why[0] = '\0';
    }
    return PMX_OK;
#undef VFAIL
}
