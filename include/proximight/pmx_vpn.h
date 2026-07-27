/*
 * pmx_vpn.h — ingest OpenVPN (.ovpn) and WireGuard (.conf) configurations.
 *
 * A VPN in ProxiMight is the *overarching* tunnel: it carries the machine's
 * traffic, and per-application proxy rules sit on top of it (app -> proxy ->
 * ... -> internet, all inside the tunnel). That layering is why the VPN needs
 * to be first-class here rather than something you set up elsewhere:
 *
 *   - The lockdown kill-switch MUST allowlist the VPN's own endpoint. Forget
 *     that and arming lockdown blocks the tunnel handshake itself — the classic
 *     way a kill switch bricks connectivity instead of protecting it.
 *   - The checker should be able to ping/trace the tunnel endpoint.
 *
 * SECRETS POLICY — read before extending this
 * -------------------------------------------
 * These files contain private keys (WireGuard `PrivateKey`, OpenVPN inline
 * <key>/<tls-auth> blocks). This parser deliberately **does not copy any secret
 * material into memory or into the profile**. It records only that a secret is
 * *present* (has_private_key, has_inline_secrets, ...) and keeps the path to
 * the original file. When a tunnel is eventually launched, the config path is
 * handed to the real client binary (openvpn / wireguard), the same way we drive
 * an external process rather than reimplementing its cryptography.
 *
 * That means: never add a `char private_key[...]` field here. The profile is
 * stored as plaintext JSON today (see docs/PRIVACY-SECURITY.md), and putting
 * tunnel keys in it would turn a known wart into a serious problem.
 *
 * NOTE: parsing a config does not establish a tunnel. Bringing the link up
 * requires the vendor client (and a driver / elevation); see docs/ROADMAP.md.
 */
#ifndef PROXIMIGHT_PMX_VPN_H
#define PROXIMIGHT_PMX_VPN_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

#define PMX_MAX_VPN_ENDPOINTS 8
#define PMX_MAX_ALLOWED_IPS 256

typedef enum pmx_vpn_kind {
    PMX_VPN_WIREGUARD = 0,
    PMX_VPN_OPENVPN,
    PMX_VPN_KIND__COUNT
} pmx_vpn_kind;

typedef struct pmx_vpn_endpoint {
    char host[PMX_MAX_HOST];
    pmx_port port;
    bool udp; /* WireGuard is always UDP; OpenVPN may be tcp */
} pmx_vpn_endpoint;

typedef struct pmx_vpn {
    pmx_id id;
    char label[PMX_MAX_LABEL];
    pmx_vpn_kind kind;
    bool enabled;

    /* Where the real config lives. This is what gets handed to the vendor
     * client; we never copy its secrets. */
    char config_path[PMX_MAX_PATH];

    /* OpenVPN configs commonly list several `remote` lines for failover. */
    pmx_vpn_endpoint endpoints[PMX_MAX_VPN_ENDPOINTS];
    size_t endpoint_count;
    /* True when the config listed MORE remotes than we can hold. This matters:
     * the kill-switch allowlist is built from these endpoints, so a remote we
     * dropped is one the tunnel can never reach once lockdown is armed — the
     * client would rotate to it and be blocked. Surfaced instead of silent. */
    bool endpoints_truncated;

    char dns[PMX_MAX_HOST]; /* declared/pushed DNS, if any */
    int mtu;                /* 0 = unspecified             */

    /* WireGuard (non-secret parts only). */
    char address[PMX_MAX_HOST];                 /* [Interface] Address       */
    char allowed_ips[PMX_MAX_ALLOWED_IPS];      /* [Peer] AllowedIPs         */
    char peer_public_key[64];                   /* public — safe to keep     */
    int persistent_keepalive;

    /* OpenVPN. */
    char cipher[64];
    char auth_digest[64];
    char dev[16]; /* tun / tap */

    /* Presence flags — never the material itself. */
    bool has_private_key;
    bool has_preshared_key;
    bool has_inline_secrets;
    bool requires_user_pass;

    /* True when AllowedIPs / redirect-gateway route everything through the
     * tunnel — i.e. this really is the overarching link. */
    bool full_tunnel;
} pmx_vpn;

void pmx_vpn_init(pmx_vpn *v);
const char *pmx_vpn_kind_str(pmx_vpn_kind k);

/* Parse from an in-memory config. Neither touches the filesystem. */
pmx_status pmx_vpn_parse_wireguard(const char *text, pmx_vpn *out);
pmx_status pmx_vpn_parse_openvpn(const char *text, pmx_vpn *out);

/* Sniff the format, parse, and record config_path. `label` defaults to the
 * file's base name when the config carries no better name. */
pmx_status pmx_vpn_load_file(const char *path, pmx_vpn *out);

/* Guess the kind from the text alone (used by load_file). */
pmx_status pmx_vpn_sniff(const char *text, pmx_vpn_kind *out_kind);

/* PMX_OK when the config is usable; otherwise *why explains. */
pmx_status pmx_vpn_validate(const pmx_vpn *v, char *why, size_t why_size);

/* ---- vendor client discovery ------------------------------------------- */
/*
 * ProxiMight does not implement tunnel crypto; it drives the vendor client as a
 * child process (the same posture as not bundling a redirection driver). These
 * binaries are installed normally by the user — they are NOT vendored into the
 * repo — so we locate them at runtime and let Settings override the path.
 *
 *   WireGuard : C:\Program Files\WireGuard\wireguard.exe
 *               (tunnel up  -> wireguard.exe /installtunnelservice <conf>)
 *   OpenVPN   : C:\Program Files\OpenVPN\bin\openvpn.exe   (Community edition,
 *               which exposes the --management control socket)
 */
typedef struct pmx_vpn_client {
    bool found;
    char path[PMX_MAX_PATH];
} pmx_vpn_client;

/* Locate the client that would bring a tunnel of this kind up. `override_path`
 * (may be NULL/empty) is tried first, then the standard install locations. */
pmx_status pmx_vpn_client_detect(pmx_vpn_kind kind, const char *override_path,
                                 pmx_vpn_client *out);

/* The command ProxiMight would run to bring `v` up, for display/diagnostics.
 * Writing it out makes the "we drive a vendor client" contract inspectable
 * rather than magic. */
pmx_status pmx_vpn_bringup_command(const pmx_vpn *v, const pmx_vpn_client *client,
                                   char *out, size_t cap);

/* ---- tunnel control ---------------------------------------------------- */
/*
 * Brings tunnels up/down by running the vendor client. Note the naming: we
 * report that the client PROCESS/SERVICE is running, not that a handshake
 * succeeded — ProxiMight does not (yet) read WireGuard's transfer counters or
 * OpenVPN's management socket, so claiming "connected" would be a guess.
 */
typedef enum pmx_vpn_state {
    PMX_VPN_DOWN = 0,
    PMX_VPN_STARTING,
    PMX_VPN_RUNNING, /* client running / tunnel service installed */
    PMX_VPN_FAILED,
    PMX_VPN_STATE__COUNT
} pmx_vpn_state;

const char *pmx_vpn_state_str(pmx_vpn_state s);

typedef struct pmx_vpn_runner pmx_vpn_runner;

pmx_vpn_runner *pmx_vpn_runner_create(void);
void pmx_vpn_runner_destroy(pmx_vpn_runner *r);

/* WireGuard needs Administrator (it installs a tunnel service); this returns
 * PMX_ERR_PERMISSION up front rather than failing obscurely. */
pmx_status pmx_vpn_up(pmx_vpn_runner *r, const pmx_vpn *v,
                      const pmx_vpn_client *client);
pmx_status pmx_vpn_down(pmx_vpn_runner *r, const pmx_vpn *v,
                        const pmx_vpn_client *client);

/* Refresh child-process states. Call once per pump. */
void pmx_vpn_runner_poll(pmx_vpn_runner *r);

pmx_vpn_state pmx_vpn_runner_state(pmx_vpn_runner *r, pmx_id vpn_id);
const char *pmx_vpn_runner_message(pmx_vpn_runner *r, pmx_id vpn_id);

/* ---- handshake verification -------------------------------------------- */
/*
 * "The client process is alive" is not the same as "the tunnel carries
 * traffic". These read the real evidence:
 *   WireGuard : `wg show <iface> dump` -> latest handshake time + rx/tx bytes
 *   OpenVPN   : the --management socket's `state` reply -> CONNECTED + local IP
 */
typedef struct pmx_vpn_status {
    bool verified;  /* we managed to query at all                    */
    bool connected; /* the evidence says the tunnel is actually up    */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t last_handshake_epoch; /* WireGuard; 0 = never            */
    char assigned_ip[PMX_MAX_IP];  /* OpenVPN local address           */
    char detail[PMX_MAX_MSG];
} pmx_vpn_status;

/* Pure parsers (unit tested; no I/O). `now_epoch` lets the WireGuard one decide
 * whether the last handshake is recent enough to call the link up. */
pmx_status pmx_wg_parse_dump(const char *text, uint64_t now_epoch,
                             pmx_vpn_status *out);
pmx_status pmx_ovpn_parse_state(const char *text, pmx_vpn_status *out);

/* Live query for a tunnel this runner started. */
pmx_status pmx_vpn_query_status(pmx_vpn_runner *r, const pmx_vpn *v,
                                const pmx_vpn_client *client,
                                pmx_vpn_status *out);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_VPN_H */
