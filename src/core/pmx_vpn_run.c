/*
 * pmx_vpn_run.c — bring tunnels up and down by driving the vendor client.
 *
 * WireGuard: `wireguard.exe /installtunnelservice <conf>` installs a Windows
 *   service that owns the tunnel; `/uninstalltunnelservice <name>` removes it.
 *   The service name is derived from the config's base name. Needs Admin.
 *
 * OpenVPN:  `openvpn.exe --config <conf>` run as a child. The OpenVPN
 *   interactive service (installed with the Community client) performs the
 *   privileged parts, so this generally works without elevating ProxiMight.
 *
 * Honesty note: "RUNNING" means the client process is alive / the tunnel
 * service is installed. It does NOT mean a handshake completed. Verifying that
 * needs WireGuard's transfer counters or OpenVPN's --management socket, which
 * is a separate step (see docs/ROADMAP.md).
 */
#include "proximight/pmx_vpn.h"
#include "proximight/pmx_proc.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* Management ports handed to OpenVPN children, one per tracked tunnel. */
#define PMX_OVPN_MGMT_BASE 25340
/* A WireGuard link with no handshake this recent is not carrying traffic. */
#define PMX_WG_HANDSHAKE_FRESH_S 180

#define PMX_VPN_MAX_TRACKED 8

typedef struct vpn_entry {
    pmx_id id;
    bool used;
    pmx_vpn_kind kind;
    pmx_vpn_state state;
    char message[PMX_MAX_MSG];
    char tunnel_name[64]; /* WireGuard service name */
    pmx_proc *proc;       /* OpenVPN child          */
    pmx_port mgmt_port;   /* OpenVPN management socket */
    bool stopping;
} vpn_entry;

struct pmx_vpn_runner {
    vpn_entry entries[PMX_VPN_MAX_TRACKED];
};

const char *pmx_vpn_state_str(pmx_vpn_state s) {
    switch (s) {
    case PMX_VPN_DOWN:     return "Down";
    case PMX_VPN_STARTING: return "Starting";
    case PMX_VPN_RUNNING:  return "Client running";
    case PMX_VPN_FAILED:   return "Failed";
    case PMX_VPN_STATE__COUNT: break;
    }
    return "?";
}

static void base_name_no_ext(const char *path, char *out, size_t cap) {
    const char *base = path;
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    if (s1 != NULL && s1 + 1 > base) base = s1 + 1;
    if (s2 != NULL && s2 + 1 > base) base = s2 + 1;
    pmx_strlcpy(out, base, cap);
    char *dot = strrchr(out, '.');
    if (dot != NULL && dot != out) {
        *dot = '\0';
    }
}

static vpn_entry *entry_for(pmx_vpn_runner *r, pmx_id id, bool create) {
    for (size_t i = 0; i < PMX_VPN_MAX_TRACKED; i++) {
        if (r->entries[i].used && r->entries[i].id == id) {
            return &r->entries[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (size_t i = 0; i < PMX_VPN_MAX_TRACKED; i++) {
        if (!r->entries[i].used) {
            memset(&r->entries[i], 0, sizeof(r->entries[i]));
            r->entries[i].used = true;
            r->entries[i].id = id;
            r->entries[i].state = PMX_VPN_DOWN;
            return &r->entries[i];
        }
    }
    /* No free slot. Slots were never released, so trying eight different
     * tunnels in one session permanently wedged the ninth. Reclaim a finished
     * one — DOWN or FAILED with no live child — keeping its status visible
     * until the space is actually needed. A RUNNING tunnel is never evicted. */
    for (size_t i = 0; i < PMX_VPN_MAX_TRACKED; i++) {
        vpn_entry *e = &r->entries[i];
        if (e->proc == NULL &&
            (e->state == PMX_VPN_DOWN || e->state == PMX_VPN_FAILED)) {
            memset(e, 0, sizeof(*e));
            e->used = true;
            e->id = id;
            e->state = PMX_VPN_DOWN;
            return e;
        }
    }
    return NULL;
}

pmx_vpn_runner *pmx_vpn_runner_create(void) {
    return (pmx_vpn_runner *)calloc(1, sizeof(pmx_vpn_runner));
}

void pmx_vpn_runner_destroy(pmx_vpn_runner *r) {
    if (r == NULL) {
        return;
    }
    for (size_t i = 0; i < PMX_VPN_MAX_TRACKED; i++) {
        if (r->entries[i].proc != NULL) {
            /* Leaving a tunnel process orphaned would be worse than stopping
             * it: the user expects closing ProxiMight to not silently keep
             * rerouting their machine. */
            pmx_proc_free(r->entries[i].proc);
            r->entries[i].proc = NULL;
        }
    }
    free(r);
}

pmx_status pmx_vpn_up(pmx_vpn_runner *r, const pmx_vpn *v,
                      const pmx_vpn_client *client) {
    if (r == NULL || v == NULL || client == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    if (!client->found) {
        return PMX_ERR_NOT_FOUND;
    }
    char why[128];
    if (pmx_vpn_validate(v, why, sizeof(why)) != PMX_OK) {
        return PMX_ERR_INVALID_ARG;
    }

    vpn_entry *e = entry_for(r, v->id, true);
    if (e == NULL) {
        return PMX_ERR_STATE;
    }
    e->kind = v->kind;
    e->stopping = false;

    if (v->kind == PMX_VPN_WIREGUARD) {
        if (!pmx_proc_is_elevated()) {
            e->state = PMX_VPN_FAILED;
            pmx_strlcpy(e->message,
                        "WireGuard needs Administrator to install the tunnel "
                        "service — restart ProxiMight elevated.",
                        sizeof(e->message));
            PMX_LOGW("[vpn] %s", e->message);
            return PMX_ERR_PERMISSION;
        }
        base_name_no_ext(v->config_path, e->tunnel_name, sizeof(e->tunnel_name));

        char cmd[PMX_MAX_PATH + 128];
        snprintf(cmd, sizeof(cmd), "\"%s\" /installtunnelservice \"%s\"",
                 client->path, v->config_path);
        char out[512];
        int code = -1;
        e->state = PMX_VPN_STARTING;
        pmx_status st = pmx_proc_run(cmd, 20000, &code, out, sizeof(out));
        if (st == PMX_OK && code == 0) {
            e->state = PMX_VPN_RUNNING;
            snprintf(e->message, sizeof(e->message),
                     "tunnel service '%s' installed (handshake not verified)",
                     e->tunnel_name);
            PMX_LOGI("[vpn] WireGuard tunnel '%s' up", e->tunnel_name);
            return PMX_OK;
        }
        e->state = PMX_VPN_FAILED;
        snprintf(e->message, sizeof(e->message), "wireguard.exe exited %d%s%s",
                 code, out[0] ? ": " : "", out);
        PMX_LOGE("[vpn] %s", e->message);
        return PMX_ERR_STATE;
    }

    /* OpenVPN: long-running child; the interactive service does the
     * privileged work. --management gives us a socket to ask whether the
     * tunnel actually came up, rather than assuming it did. */
    if (e->mgmt_port == 0) {
        size_t slot = (size_t)(e - r->entries);
        e->mgmt_port = (pmx_port)(PMX_OVPN_MGMT_BASE + slot);
    }
    char cmd[PMX_MAX_PATH + 128];
    snprintf(cmd, sizeof(cmd), "\"%s\" --config \"%s\" --management 127.0.0.1 %u",
             client->path, v->config_path, (unsigned)e->mgmt_port);
    if (e->proc != NULL) {
        pmx_proc_free(e->proc);
        e->proc = NULL;
    }
    e->state = PMX_VPN_STARTING;
    pmx_status st = pmx_proc_spawn(cmd, &e->proc);
    if (st != PMX_OK) {
        e->state = PMX_VPN_FAILED;
        pmx_strlcpy(e->message,
                    st == PMX_ERR_PERMISSION
                        ? "openvpn.exe needs elevation (is the interactive "
                          "service running?)"
                        : "could not start openvpn.exe",
                    sizeof(e->message));
        PMX_LOGE("[vpn] %s", e->message);
        return st;
    }
    pmx_strlcpy(e->message, "openvpn client started (handshake not verified)",
                sizeof(e->message));
    PMX_LOGI("[vpn] OpenVPN client started for '%s'", v->label);
    return PMX_OK;
}

pmx_status pmx_vpn_down(pmx_vpn_runner *r, const pmx_vpn *v,
                        const pmx_vpn_client *client) {
    if (r == NULL || v == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    vpn_entry *e = entry_for(r, v->id, false);
    if (e == NULL) {
        return PMX_OK; /* never started */
    }
    e->stopping = true;

    if (v->kind == PMX_VPN_WIREGUARD) {
        if (client == NULL || !client->found) {
            return PMX_ERR_NOT_FOUND;
        }
        if (e->tunnel_name[0] == '\0') {
            base_name_no_ext(v->config_path, e->tunnel_name,
                             sizeof(e->tunnel_name));
        }
        char cmd[PMX_MAX_PATH + 128];
        snprintf(cmd, sizeof(cmd), "\"%s\" /uninstalltunnelservice \"%s\"",
                 client->path, e->tunnel_name);
        int code = -1;
        char out[256];
        pmx_proc_run(cmd, 20000, &code, out, sizeof(out));
        e->state = PMX_VPN_DOWN;
        pmx_strlcpy(e->message, "tunnel service removed", sizeof(e->message));
        PMX_LOGI("[vpn] WireGuard tunnel '%s' down", e->tunnel_name);
        return PMX_OK;
    }

    if (e->proc != NULL) {
        pmx_proc_free(e->proc); /* kills if still running */
        e->proc = NULL;
    }
    e->state = PMX_VPN_DOWN;
    pmx_strlcpy(e->message, "openvpn client stopped", sizeof(e->message));
    PMX_LOGI("[vpn] OpenVPN client stopped for '%s'", v->label);
    return PMX_OK;
}

void pmx_vpn_runner_poll(pmx_vpn_runner *r) {
    if (r == NULL) {
        return;
    }
    for (size_t i = 0; i < PMX_VPN_MAX_TRACKED; i++) {
        vpn_entry *e = &r->entries[i];
        if (!e->used || e->proc == NULL) {
            continue;
        }
        if (pmx_proc_running(e->proc)) {
            if (e->state == PMX_VPN_STARTING) {
                e->state = PMX_VPN_RUNNING;
            }
            continue;
        }
        /* The child exited on its own. */
        int code = pmx_proc_exit_code(e->proc);
        pmx_proc_free(e->proc);
        e->proc = NULL;
        if (e->stopping) {
            e->state = PMX_VPN_DOWN;
        } else {
            e->state = PMX_VPN_FAILED;
            snprintf(e->message, sizeof(e->message),
                     "openvpn exited unexpectedly (code %d) — check its log",
                     code);
            PMX_LOGW("[vpn] %s", e->message);
        }
    }
}

pmx_vpn_state pmx_vpn_runner_state(pmx_vpn_runner *r, pmx_id vpn_id) {
    if (r == NULL) {
        return PMX_VPN_DOWN;
    }
    vpn_entry *e = entry_for(r, vpn_id, false);
    return e != NULL ? e->state : PMX_VPN_DOWN;
}

const char *pmx_vpn_runner_message(pmx_vpn_runner *r, pmx_id vpn_id) {
    if (r == NULL) {
        return "";
    }
    vpn_entry *e = entry_for(r, vpn_id, false);
    return (e != NULL) ? e->message : "";
}

/* ------------------------------------------- handshake verification ------ */

/* Split `line` in place on `sep`. Returns the field count. */
static size_t split_fields(char *line, char sep, char **f, size_t max) {
    size_t n = 0;
    char *p = line;
    while (n < max) {
        f[n++] = p;
        char *s = strchr(p, sep);
        if (s == NULL) {
            break;
        }
        *s = '\0';
        p = s + 1;
    }
    return n;
}

/* Copy the next line out of *p (advancing it). Returns false at the end. */
static bool next_line(const char **p, char *line, size_t cap) {
    if (**p == '\0') {
        return false;
    }
    const char *nl = strchr(*p, '\n');
    size_t len = nl ? (size_t)(nl - *p) : strlen(*p);
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(line, *p, len);
    line[len] = '\0';
    *p = nl ? nl + 1 : *p + strlen(*p);
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n')) {
        line[--l] = '\0';
    }
    return true;
}

pmx_status pmx_wg_parse_dump(const char *text, uint64_t now_epoch,
                             pmx_vpn_status *out) {
    if (text == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    bool saw_peer = false;
    const char *p = text;
    char line[1024];
    while (next_line(&p, line, sizeof(line))) {
        if (line[0] == '\0') {
            continue;
        }
        char *f[10];
        size_t n = split_fields(line, '\t', f, 10);
        /* The interface line has 4 fields; peers have 8. */
        if (n < 8) {
            continue;
        }
        saw_peer = true;
        uint64_t hs = strtoull(f[4], NULL, 10);
        if (hs > out->last_handshake_epoch) {
            out->last_handshake_epoch = hs;
        }
        out->rx_bytes += strtoull(f[5], NULL, 10);
        out->tx_bytes += strtoull(f[6], NULL, 10);
    }

    if (!saw_peer) {
        pmx_strlcpy(out->detail, "wg reported no peer", sizeof(out->detail));
        return PMX_ERR_PARSE;
    }
    out->verified = true;
    if (out->last_handshake_epoch == 0) {
        out->connected = false;
        pmx_strlcpy(out->detail, "no handshake yet", sizeof(out->detail));
        return PMX_OK;
    }
    uint64_t age = (now_epoch > out->last_handshake_epoch)
                       ? (now_epoch - out->last_handshake_epoch)
                       : 0;
    out->connected = (age <= PMX_WG_HANDSHAKE_FRESH_S);
    snprintf(out->detail, sizeof(out->detail),
             "handshake %llus ago • rx %llu / tx %llu bytes",
             (unsigned long long)age, (unsigned long long)out->rx_bytes,
             (unsigned long long)out->tx_bytes);
    return PMX_OK;
}

pmx_status pmx_ovpn_parse_state(const char *text, pmx_vpn_status *out) {
    if (text == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    bool found = false;
    const char *p = text;
    char line[1024];
    while (next_line(&p, line, sizeof(line))) {
        if (line[0] == '\0' || line[0] == '>' || strcmp(line, "END") == 0) {
            continue; /* async notices and the terminator */
        }
        /* A state line starts with a unix timestamp. */
        if (line[0] < '0' || line[0] > '9') {
            continue;
        }
        char *f[10];
        size_t n = split_fields(line, ',', f, 10);
        if (n < 2) {
            continue;
        }
        found = true;
        out->verified = true;
        out->connected = (strcmp(f[1], "CONNECTED") == 0);
        if (n > 3 && f[3][0] != '\0') {
            pmx_strlcpy(out->assigned_ip, f[3], sizeof(out->assigned_ip));
        }
        if (n > 2 && f[2][0] != '\0' && strcmp(f[2], "SUCCESS") != 0) {
            snprintf(out->detail, sizeof(out->detail), "%s (%s)", f[1], f[2]);
        } else if (out->assigned_ip[0] != '\0') {
            snprintf(out->detail, sizeof(out->detail), "%s • %s", f[1],
                     out->assigned_ip);
        } else {
            pmx_strlcpy(out->detail, f[1], sizeof(out->detail));
        }
        break; /* first state line wins */
    }
    if (!found) {
        pmx_strlcpy(out->detail, "no state line in management reply",
                    sizeof(out->detail));
        return PMX_ERR_PARSE;
    }
    return PMX_OK;
}

pmx_status pmx_vpn_query_status(pmx_vpn_runner *r, const pmx_vpn *v,
                                const pmx_vpn_client *client,
                                pmx_vpn_status *out) {
    if (r == NULL || v == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    vpn_entry *e = entry_for(r, v->id, false);
    if (e == NULL) {
        pmx_strlcpy(out->detail, "not started by ProxiMight",
                    sizeof(out->detail));
        return PMX_ERR_NOT_FOUND;
    }

    if (v->kind == PMX_VPN_WIREGUARD) {
        if (client == NULL || !client->found) {
            pmx_strlcpy(out->detail, "WireGuard client not found",
                        sizeof(out->detail));
            return PMX_ERR_NOT_FOUND;
        }
        if (e->tunnel_name[0] == '\0') {
            base_name_no_ext(v->config_path, e->tunnel_name,
                             sizeof(e->tunnel_name));
        }
        /* wg.exe ships beside wireguard.exe. */
        char dir[PMX_MAX_PATH];
        pmx_strlcpy(dir, client->path, sizeof(dir));
        char *slash = strrchr(dir, '\\');
        if (slash == NULL) {
            slash = strrchr(dir, '/');
        }
        if (slash != NULL) {
            *slash = '\0';
        } else {
            dir[0] = '\0';
        }

        char cmd[PMX_MAX_PATH + 128];
        /* Quote the tunnel name like every other interpolation here: it comes
         * from the config FILENAME, so "US East.conf" would otherwise split
         * into two arguments and wg would fail with a misleading
         * "usually needs Administrator". */
        snprintf(cmd, sizeof(cmd), "\"%s\\wg.exe\" show \"%s\" dump", dir,
                 e->tunnel_name);
        char text[4096];
        int code = -1;
        pmx_status st = pmx_proc_run(cmd, 5000, &code, text, sizeof(text));
        if (st != PMX_OK || code != 0) {
            snprintf(out->detail, sizeof(out->detail),
                     "wg show failed (exit %d) — usually needs Administrator",
                     code);
            return PMX_ERR_STATE;
        }
        return pmx_wg_parse_dump(text, (uint64_t)time(NULL), out);
    }

    /* OpenVPN: ask the management socket. */
    if (e->mgmt_port == 0) {
        pmx_strlcpy(out->detail, "no management port for this tunnel",
                    sizeof(out->detail));
        return PMX_ERR_STATE;
    }
    pmx_socket s = PMX_INVALID_SOCKET;
    if (pmx_tcp_connect("127.0.0.1", e->mgmt_port, 1500, &s) != PMX_OK) {
        pmx_strlcpy(out->detail,
                    "management socket unreachable (is the client running?)",
                    sizeof(out->detail));
        return PMX_ERR_NET;
    }
    pmx_send_all(s, "state\n", 6);

    char buf[4096];
    size_t total = 0;
    for (int i = 0; i < 8 && total < sizeof(buf) - 1; i++) {
        size_t got = 0;
        if (pmx_recv_some(s, buf + total, sizeof(buf) - 1 - total, &got, 400) !=
            PMX_OK) {
            break;
        }
        total += got;
        buf[total] = '\0';
        if (strstr(buf, "\nEND") != NULL || strstr(buf, "\rEND") != NULL) {
            break;
        }
    }
    buf[total] = '\0';
    pmx_socket_close(s);
    return pmx_ovpn_parse_state(buf, out);
}
