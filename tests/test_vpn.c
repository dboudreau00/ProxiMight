/*
 * test_vpn.c — OpenVPN / WireGuard config ingestion.
 *
 * Two things beyond "does it parse":
 *   1. Directive-looking text inside an inline <ca>/<key> block must NOT be
 *      interpreted as configuration. A certificate body containing the word
 *      "remote" must not add an endpoint — that would be a config-injection
 *      bug with real consequences (traffic sent somewhere you never chose).
 *   2. No secret material may end up anywhere in the parsed struct. We scan the
 *      raw bytes to prove it.
 */
#include "pmx_test.h"
#include "proximight/pmx_vpn.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdio.h>

static const char *kWireguard =
    "[Interface]\n"
    "PrivateKey = SECRETPRIVATEKEYVALUE00000000000000000000=\n"
    "Address = 10.66.66.2/32, fd42::2/128\n"
    "DNS = 1.1.1.1\n"
    "MTU = 1420\n"
    "\n"
    "[Peer]\n"
    "PublicKey = PEERPUBLICKEY1111111111111111111111111111=\n"
    "PresharedKey = SECRETPRESHAREDKEY222222222222222222222=\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = vpn.example.com:51820\n"
    "PersistentKeepalive = 25\n";

static const char *kOpenvpn =
    "client\n"
    "dev tun\n"
    "proto udp\n"
    "remote vpn1.example.com 1194\n"
    "remote vpn2.example.com 443 tcp\n"
    "cipher AES-256-GCM\n"
    "auth SHA512\n"
    "auth-user-pass\n"
    "redirect-gateway def1\n"
    "tun-mtu 1400\n"
    "dhcp-option DNS 9.9.9.9\n"
    "# a comment mentioning remote decoy.example.com 9999\n"
    "<ca>\n"
    "-----BEGIN CERTIFICATE-----\n"
    "remote evil.example.com 1234\n"
    "-----END CERTIFICATE-----\n"
    "</ca>\n"
    "<key>\n"
    "-----BEGIN PRIVATE KEY-----\n"
    "SECRETOPENVPNKEYMATERIAL\n"
    "-----END PRIVATE KEY-----\n"
    "</key>\n";

/* Does the struct's raw memory contain this string anywhere? */
static bool bytes_contain(const void *obj, size_t n, const char *needle) {
    size_t ln = strlen(needle);
    const char *b = (const char *)obj;
    if (ln == 0 || ln > n) {
        return false;
    }
    for (size_t i = 0; i + ln <= n; i++) {
        if (memcmp(b + i, needle, ln) == 0) {
            return true;
        }
    }
    return false;
}

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    /* ---------------- WireGuard ---------------- */
    pmx_vpn wg;
    CHECK(pmx_vpn_parse_wireguard(kWireguard, &wg) == PMX_OK);
    CHECK_EQ_INT(wg.kind, PMX_VPN_WIREGUARD);
    CHECK_EQ_INT(wg.endpoint_count, 1);
    if (wg.endpoint_count == 1) {
        CHECK_STR_EQ(wg.endpoints[0].host, "vpn.example.com");
        CHECK_EQ_INT(wg.endpoints[0].port, 51820);
        CHECK(wg.endpoints[0].udp);
    }
    CHECK_STR_EQ(wg.dns, "1.1.1.1");
    CHECK_EQ_INT(wg.mtu, 1420);
    CHECK_EQ_INT(wg.persistent_keepalive, 25);
    CHECK(wg.full_tunnel); /* AllowedIPs 0.0.0.0/0 */
    CHECK(wg.has_private_key);
    CHECK(wg.has_preshared_key);
    CHECK_STR_EQ(wg.peer_public_key, "PEERPUBLICKEY1111111111111111111111111111=");

    /* Secrets must not have been copied anywhere into the struct. */
    CHECK(!bytes_contain(&wg, sizeof(wg), "SECRETPRIVATEKEYVALUE"));
    CHECK(!bytes_contain(&wg, sizeof(wg), "SECRETPRESHAREDKEY"));

    /* ---------------- OpenVPN ---------------- */
    pmx_vpn ov;
    CHECK(pmx_vpn_parse_openvpn(kOpenvpn, &ov) == PMX_OK);
    CHECK_EQ_INT(ov.kind, PMX_VPN_OPENVPN);

    /* Exactly the two real remotes — the one inside <ca> and the one in the
     * comment must both be ignored. */
    CHECK_EQ_INT(ov.endpoint_count, 2);
    if (ov.endpoint_count == 2) {
        CHECK_STR_EQ(ov.endpoints[0].host, "vpn1.example.com");
        CHECK_EQ_INT(ov.endpoints[0].port, 1194);
        CHECK(ov.endpoints[0].udp);
        CHECK_STR_EQ(ov.endpoints[1].host, "vpn2.example.com");
        CHECK_EQ_INT(ov.endpoints[1].port, 443);
        CHECK(!ov.endpoints[1].udp); /* explicit tcp */
    }
    CHECK(!bytes_contain(&ov, sizeof(ov), "evil.example.com"));
    CHECK(!bytes_contain(&ov, sizeof(ov), "decoy.example.com"));
    CHECK(!bytes_contain(&ov, sizeof(ov), "SECRETOPENVPNKEYMATERIAL"));

    CHECK_STR_EQ(ov.cipher, "AES-256-GCM");
    CHECK_STR_EQ(ov.auth_digest, "SHA512");
    CHECK_STR_EQ(ov.dev, "tun");
    CHECK_STR_EQ(ov.dns, "9.9.9.9");
    CHECK_EQ_INT(ov.mtu, 1400);
    CHECK(ov.requires_user_pass);
    CHECK(ov.full_tunnel);
    CHECK(ov.has_inline_secrets);

    /* --- config injection via an UNRECOGNIZED inline block -------------------
     * Regression: the parser used to allowlist ten known tags and parse the body
     * of every other <tag> block as configuration. OpenVPN treats ANY <tag> as
     * an inline file, so a `remote` hidden in one was injected as a real
     * endpoint — and pmx_engine copies endpoints into the lockdown ALLOWLIST,
     * i.e. a hostile config could punch a hole through the kill switch. */
    static const char *const kInjectTags[] = {"auth-user-pass", "crl-verify",
                                              "peer-fingerprint",
                                              "http-proxy-user-pass"};
    for (size_t i = 0; i < sizeof(kInjectTags) / sizeof(kInjectTags[0]); i++) {
        char cfg[512];
        snprintf(cfg, sizeof(cfg),
                 "client\ndev tun\nproto udp\nremote real.example.com 1194\n"
                 "<%s>\nalice\nhunter2\nremote evil.example.com 443 tcp\n"
                 "auth LEAKEDSECRET extra\n</%s>\n",
                 kInjectTags[i], kInjectTags[i]);
        pmx_vpn inj;
        CHECK(pmx_vpn_parse_openvpn(cfg, &inj) == PMX_OK);
        CHECK_EQ_INT(inj.endpoint_count, 1); /* ONLY the real remote */
        if (inj.endpoint_count >= 1) {
            CHECK_STR_EQ(inj.endpoints[0].host, "real.example.com");
        }
        /* Nothing from inside the block may reach the struct at all. */
        CHECK(!bytes_contain(&inj, sizeof(inj), "evil.example.com"));
        CHECK(!bytes_contain(&inj, sizeof(inj), "LEAKEDSECRET"));
    }

    /* A stray mis-cased close must NOT end the block early (OpenVPN matches the
     * closing tag case-sensitively; ending early resumes parsing at a point
     * OpenVPN still treats as certificate data). */
    const char *case_cfg = "client\nremote real.example.com 1194\n"
                           "<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n"
                           "</CA>\nremote evil2.example.com 8443\n</ca>\n";
    pmx_vpn cv;
    CHECK(pmx_vpn_parse_openvpn(case_cfg, &cv) == PMX_OK);
    CHECK_EQ_INT(cv.endpoint_count, 1);
    CHECK(!bytes_contain(&cv, sizeof(cv), "evil2.example.com"));

    /* <connection> stays parsed inline — it really is configuration. */
    const char *conn_cfg = "client\n<connection>\nremote c1.example.com 1195 tcp\n"
                           "</connection>\n";
    pmx_vpn cc;
    CHECK(pmx_vpn_parse_openvpn(conn_cfg, &cc) == PMX_OK);
    CHECK_EQ_INT(cc.endpoint_count, 1);
    if (cc.endpoint_count == 1) {
        CHECK_STR_EQ(cc.endpoints[0].host, "c1.example.com");
    }

    /* ...but ONLY in that exact spelling. OpenVPN matches option names
     * case-sensitively, so it treats <Connection> as an unrecognized inline
     * FILE and never reads the body. Accepting it case-insensitively here would
     * parse a block OpenVPN ignores — an injection vector that also feeds the
     * kill-switch allowlist. */
    static const char *const kCaseVariants[] = {"Connection", "CONNECTION",
                                                "ConNection"};
    for (size_t i = 0; i < sizeof(kCaseVariants) / sizeof(kCaseVariants[0]); i++) {
        char cfg[384];
        snprintf(cfg, sizeof(cfg),
                 "client\nremote real.example.com 1194\n"
                 "<%s>\nremote evil.example.com 443 tcp\n</%s>\n",
                 kCaseVariants[i], kCaseVariants[i]);
        pmx_vpn cv2;
        CHECK(pmx_vpn_parse_openvpn(cfg, &cv2) == PMX_OK);
        CHECK_EQ_INT(cv2.endpoint_count, 1); /* ONLY the real remote */
        CHECK(!bytes_contain(&cv2, sizeof(cv2), "evil.example.com"));
    }

    /* A remote with no port inherits the global `port` directive. */
    const char *port_cfg = "proto tcp\nport 1195\nremote a.example.com\n";
    pmx_vpn pv;
    CHECK(pmx_vpn_parse_openvpn(port_cfg, &pv) == PMX_OK);
    CHECK_EQ_INT(pv.endpoint_count, 1);
    if (pv.endpoint_count == 1) {
        CHECK_EQ_INT(pv.endpoints[0].port, 1195);
        CHECK(!pv.endpoints[0].udp); /* proto tcp */
    }

    /* --- a UTF-8 BOM must not hide the [Interface] section -------------------
     * Editors on Windows save configs BOM-first; the three bytes glued
     * themselves to "[Interface]", so the section never matched and a perfectly
     * good config was rejected with "no PrivateKey". */
    const char *bom_cfg = "\xEF\xBB\xBF[Interface]\nPrivateKey = QUJD\n"
                          "Address = 10.9.0.2/32\n\n[Peer]\n"
                          "PublicKey = WFla\nEndpoint = vpn.example.com:51820\n"
                          "AllowedIPs = 0.0.0.0/0\n";
    pmx_vpn bomv;
    CHECK(pmx_vpn_parse_wireguard(bom_cfg, &bomv) == PMX_OK);
    CHECK(bomv.has_private_key);
    CHECK_STR_EQ(bomv.address, "10.9.0.2/32");
    CHECK(bomv.full_tunnel);
    pmx_vpn_kind bk;
    CHECK(pmx_vpn_sniff(bom_cfg, &bk) == PMX_OK);
    CHECK_EQ_INT(bk, PMX_VPN_WIREGUARD);

    /* --- the two-halves idiom really is a FULL tunnel ------------------------
     * 0.0.0.0/1 + 128.0.0.0/1 covers all of IPv4. Badging that "split tunnel"
     * would be an inverted privacy claim. */
    const char *halves = "[Interface]\nPrivateKey = QUJD\n[Peer]\n"
                         "Endpoint = vpn.example.com:51820\n"
                         "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n";
    pmx_vpn hv;
    CHECK(pmx_vpn_parse_wireguard(halves, &hv) == PMX_OK);
    CHECK(hv.full_tunnel);

    /* A genuine split tunnel must still read as split. */
    const char *split = "[Interface]\nPrivateKey = QUJD\n[Peer]\n"
                        "Endpoint = vpn.example.com:51820\n"
                        "AllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n";
    pmx_vpn sv;
    CHECK(pmx_vpn_parse_wireguard(split, &sv) == PMX_OK);
    CHECK(!sv.full_tunnel);

    /* --- dropping remotes past the cap must be REPORTED, not silent ----------
     * lockdown allowlists these endpoints, so a remote we never recorded is one
     * the tunnel can never reach once the kill switch is armed. */
    {
        char many[2048];
        int n = snprintf(many, sizeof(many), "client\ndev tun\nproto udp\n");
        for (int i = 0; i < PMX_MAX_VPN_ENDPOINTS + 4; i++) {
            n += snprintf(many + n, sizeof(many) - (size_t)n,
                          "remote r%d.example.com 1194\n", i);
        }
        pmx_vpn mv;
        CHECK(pmx_vpn_parse_openvpn(many, &mv) == PMX_OK);
        CHECK_EQ_INT(mv.endpoint_count, PMX_MAX_VPN_ENDPOINTS);
        CHECK(mv.endpoints_truncated);
    }
    /* A config that fits must NOT claim truncation. */
    CHECK(!ov.endpoints_truncated);

    /* ---------------- sniffing ---------------- */
    pmx_vpn_kind k;
    CHECK(pmx_vpn_sniff(kWireguard, &k) == PMX_OK);
    CHECK_EQ_INT(k, PMX_VPN_WIREGUARD);
    CHECK(pmx_vpn_sniff(kOpenvpn, &k) == PMX_OK);
    CHECK_EQ_INT(k, PMX_VPN_OPENVPN);
    CHECK(pmx_vpn_sniff("this is not a vpn config", &k) == PMX_ERR_PARSE);

    /* ---------------- validation ---------------- */
    char why[128];
    CHECK(pmx_vpn_validate(&wg, why, sizeof(why)) != PMX_OK); /* no config_path */
    pmx_strlcpy(wg.config_path, "C:\\tmp\\wg.conf", sizeof(wg.config_path));
    CHECK(pmx_vpn_validate(&wg, why, sizeof(why)) == PMX_OK);

    pmx_vpn empty;
    pmx_vpn_init(&empty);
    CHECK(pmx_vpn_validate(&empty, why, sizeof(why)) != PMX_OK);
    CHECK(why[0] != '\0');

    /* ---------------- load from disk ---------------- */
    const char *tmp = "test_vpn_sample.conf";
    FILE *f = fopen(tmp, "wb");
    CHECK(f != NULL);
    if (f != NULL) {
        fwrite(kWireguard, 1, strlen(kWireguard), f);
        fclose(f);
        pmx_vpn loaded;
        CHECK(pmx_vpn_load_file(tmp, &loaded) == PMX_OK);
        CHECK_EQ_INT(loaded.kind, PMX_VPN_WIREGUARD);
        CHECK_EQ_INT(loaded.endpoint_count, 1);
        CHECK_STR_EQ(loaded.label, "test_vpn_sample"); /* basename, no ext */
        CHECK_STR_EQ(loaded.config_path, tmp);
        CHECK(!bytes_contain(&loaded, sizeof(loaded), "SECRETPRIVATEKEYVALUE"));
        remove(tmp);
    }

    /* ---------------- handshake verification parsers ---------------- */
    /* `wg show <if> dump`: a 4-field interface line, then 8-field peers. */
    static const char *wg_dump =
        "PRIVKEYAAA\tPUBKEYBBB\t51820\toff\n"
        "PEERPUB1\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t1700000000\t1000\t2000\t25\n"
        "PEERPUB2\t(none)\t5.6.7.8:51820\t10.0.0.0/8\t1700000030\t500\t700\t0\n";

    pmx_vpn_status ws;
    CHECK(pmx_wg_parse_dump(wg_dump, 1700000060ULL, &ws) == PMX_OK);
    CHECK(ws.verified);
    CHECK(ws.connected); /* newest handshake is 30s old */
    CHECK_EQ_INT(ws.rx_bytes, 1500);
    CHECK_EQ_INT(ws.tx_bytes, 2700);
    CHECK_EQ_INT(ws.last_handshake_epoch, 1700000030);

    /* A stale handshake is not a live tunnel. */
    CHECK(pmx_wg_parse_dump(wg_dump, 1700009999ULL, &ws) == PMX_OK);
    CHECK(ws.verified);
    CHECK(!ws.connected);

    /* Never handshaked. */
    static const char *wg_never =
        "PRIV\tPUB\t51820\toff\n"
        "PEER\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t0\t0\t0\t0\n";
    CHECK(pmx_wg_parse_dump(wg_never, 1700000060ULL, &ws) == PMX_OK);
    CHECK(ws.verified);
    CHECK(!ws.connected);

    /* Interface line only -> nothing to judge. */
    CHECK(pmx_wg_parse_dump("PRIV\tPUB\t51820\toff\n", 1700000060ULL, &ws) ==
          PMX_ERR_PARSE);

    /* OpenVPN management `state` reply. */
    static const char *ovpn_up =
        ">INFO:OpenVPN Management Interface Version 5 -- type 'help'\n"
        "1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.10,1194,,\n"
        "END\n";
    pmx_vpn_status os;
    CHECK(pmx_ovpn_parse_state(ovpn_up, &os) == PMX_OK);
    CHECK(os.verified);
    CHECK(os.connected);
    CHECK_STR_EQ(os.assigned_ip, "10.8.0.2");

    static const char *ovpn_mid = "1700000000,GET_CONFIG,,,,,,\nEND\n";
    CHECK(pmx_ovpn_parse_state(ovpn_mid, &os) == PMX_OK);
    CHECK(os.verified);
    CHECK(!os.connected);

    /* Greeting only: we must not invent a state. */
    CHECK(pmx_ovpn_parse_state(">INFO:hello\nEND\n", &os) == PMX_ERR_PARSE);
    CHECK(!os.connected);

    return pmx_test_report();
}
