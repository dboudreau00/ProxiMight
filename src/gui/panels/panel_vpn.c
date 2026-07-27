#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static bool vpn_row(gui_app *app, const pmx_vpn *v) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    float availw = 0;
    guix_content_avail(&availw, NULL);
    float h = 48.0f * s;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    char id[48];
    snprintf(id, sizeof(id), "##vpnrow%llu", (unsigned long long)v->id);
    bool pressed = igInvisibleButton(id, v2(availw, h), 0);
    bool hovered = igIsItemHovered(0);
    bool selected = (app->sel_vpn == v->id);

    unsigned bg = selected ? gui_theme_u32a(t->accent, t->dark ? 0.18f : 0.12f)
                           : (hovered ? gui_theme_u32(t->surface2) : 0);
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + availw, y0 + h, bg, 8 * s);
    }
    if (selected) {
        guix_draw_rect_filled(x0, y0 + 8 * s, x0 + 3 * s, y0 + h - 8 * s,
                              gui_theme_u32(t->accent), 2 * s);
    }
    gui_icon(GUI_ICON_LOCK, x0 + 12 * s, y0 + (h - 22 * s) * 0.5f, 22 * s,
             gui_theme_u32(v->enabled ? (selected ? t->accent : t->text_dim)
                                      : t->text_faint));
    guix_draw_text(x0 + 42 * s, y0 + 8 * s, gui_theme_u32(t->text), v->label);

    char sub[320];
    if (v->endpoint_count > 0) {
        snprintf(sub, sizeof(sub), "%s  •  %s:%u%s", pmx_vpn_kind_str(v->kind),
                 v->endpoints[0].host, (unsigned)v->endpoints[0].port,
                 v->full_tunnel ? "  •  full tunnel" : "");
    } else {
        snprintf(sub, sizeof(sub), "%s  •  no endpoint", pmx_vpn_kind_str(v->kind));
    }
    guix_draw_text(x0 + 42 * s, y0 + h - 20 * s, gui_theme_u32(t->text_dim), sub);
    return pressed;
}

static void kv_row(const gui_theme *t, const char *k, const char *v) {
    if (v == NULL || v[0] == '\0') {
        return;
    }
    gui_field_label(k);
    igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text[0], t->text[1], t->text[2], 1));
    igTextWrapped("%s", v);
    igPopStyleColor(1);
}

static void vpn_editor(gui_app *app, pmx_vpn *v) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    gui_section_header(GUI_ICON_LOCK, v->label[0] ? v->label : "VPN",
                       pmx_vpn_kind_str(v->kind));
    gui_vspace(8 * s);

    /* ---- tunnel control ---- */
    {
        pmx_vpn_runner *runner = pmx_engine_vpn_runner(app->engine);
        pmx_vpn_client client;
        pmx_vpn_client_detect(v->kind,
                              v->kind == PMX_VPN_WIREGUARD
                                  ? pf->settings.wireguard_path
                                  : pf->settings.openvpn_path,
                              &client);
        pmx_vpn_state st = pmx_vpn_runner_state(runner, v->id);
        const float *sc = (st == PMX_VPN_RUNNING)  ? t->ok
                          : (st == PMX_VPN_FAILED) ? t->danger
                          : (st == PMX_VPN_STARTING) ? t->warn
                                                     : t->text_faint;
        gui_status_pill(pmx_vpn_state_str(st), sc);

        const char *msg = pmx_vpn_runner_message(runner, v->id);
        if (msg != NULL && msg[0] != '\0') {
            igTextDisabled("%s", msg);
        }

        /* Verified state: ask wg / the management socket, throttled. */
        if (st == PMX_VPN_RUNNING) {
            uint64_t now = pmx_now_ms();
            bool stale = !app->vpn_status_valid ||
                         app->vpn_status_id != v->id ||
                         now >= app->vpn_status_next_ms;
            if (stale) {
                pmx_vpn_query_status(runner, v, &client, &app->vpn_status);
                app->vpn_status_id = v->id;
                app->vpn_status_valid = true;
                app->vpn_status_next_ms = now + 5000;
            }
            const pmx_vpn_status *vs = &app->vpn_status;
            gui_vspace(4 * s);
            if (vs->verified) {
                gui_status_pill(vs->connected ? "Handshake verified — connected"
                                              : "Client up, but no traffic yet",
                                vs->connected ? t->ok : t->warn);
            } else {
                gui_status_pill("Could not verify", t->text_faint);
            }
            if (vs->detail[0] != '\0') {
                igTextDisabled("%s", vs->detail);
            }
            igSameLine(0, 10 * s);
            if (gui_ghost_button("Refresh", GUI_ICON_REFRESH)) {
                app->vpn_status_next_ms = 0;
            }
        }
        gui_vspace(6 * s);

        if (st == PMX_VPN_RUNNING || st == PMX_VPN_STARTING) {
            if (gui_danger_button("Disconnect", GUI_ICON_STOP)) {
                pmx_vpn_down(runner, v, &client);
                gui_app_status(app, "Tunnel stopped.");
            }
        } else {
            if (gui_primary_button("Connect", GUI_ICON_PLAY)) {
                if (!client.found) {
                    gui_app_status(app,
                                   "That VPN client isn't installed — see the "
                                   "VPN clients card above.");
                } else {
                    pmx_status r = pmx_vpn_up(runner, v, &client);
                    gui_app_status(app,
                                   r == PMX_OK ? "Tunnel starting…"
                                   : r == PMX_ERR_PERMISSION
                                       ? "Needs Administrator (WireGuard installs "
                                         "a tunnel service)."
                                       : "Could not start the tunnel — see the log.");
                }
            }
            if (v->kind == PMX_VPN_WIREGUARD && !pmx_proc_is_elevated()) {
                igSameLine(0, 10 * s);
                igTextDisabled("(not elevated)");
            }
        }
        gui_vspace(6 * s);
        gui_note(GUI_ICON_SHIELD,
                 "Connecting reroutes this machine's traffic through the tunnel. "
                 "ProxiMight reports that the client is running — it does not yet "
                 "verify the handshake actually completed.",
                 t->warn);
        gui_vspace(10 * s);
    }

    gui_field_label("Label");
    gui_input_text("##vpnlabel", "Tunnel name", v->label, sizeof(v->label), false);
    gui_vspace(6 * s);

    igTextUnformatted("Enabled", NULL);
    igSameLine(0, 10 * s);
    gui_toggle("##vpnen", &v->enabled);
    igSameLine(0, 16 * s);
    if (v->full_tunnel) {
        gui_badge("full tunnel", gui_theme_u32a(t->accent, 0.18f),
                  gui_theme_u32(t->accent));
    } else {
        gui_badge("split tunnel", gui_theme_u32a(t->warn, 0.18f),
                  gui_theme_u32(t->warn));
    }
    gui_vspace(10 * s);

    /* Endpoints. */
    gui_field_label("Endpoints (allowlisted by lockdown so the tunnel can come up)");
    if (igBeginTable("##vpneps", 3,
                     ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                         ImGuiTableFlags_SizingStretchProp,
                     v2(0, 0), 0)) {
        igTableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.6f, 0);
        igTableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 70 * s, 0);
        igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 110 * s, 0);
        igTableHeadersRow();
        for (size_t i = 0; i < v->endpoint_count; i++) {
            igTableNextRow(0, 0);
            igPushID_Int((int)i + 1);
            igTableSetColumnIndex(0);
            igTextUnformatted(v->endpoints[i].host, NULL);
            igTableSetColumnIndex(1);
            char pb[32];
            snprintf(pb, sizeof(pb), "%u/%s", (unsigned)v->endpoints[i].port,
                     v->endpoints[i].udp ? "udp" : "tcp");
            igTextUnformatted(pb, NULL);
            igTableSetColumnIndex(2);
            if (gui_secondary_button("Trace path", GUI_ICON_ROUTE)) {
                gui_app_start_path_scan(app, v->endpoints[i].host);
            }
            igPopID();
        }
        igEndTable();
    }
    /* A config can list more remotes than we track. Only the ones above are
     * allowlisted, so failing over to a dropped one is blocked by our own kill
     * switch — the user needs to know that, not just see a tidy list. */
    if (v->endpoints_truncated) {
        gui_vspace(6 * s);
        gui_note(GUI_ICON_SHIELD,
                 "This config lists more remotes than ProxiMight tracks. The "
                 "extra ones are NOT allowlisted — if the client fails over to "
                 "one, lockdown will block the tunnel.",
                 t->warn);
    }
    gui_vspace(10 * s);

    /* Parsed details. */
    kv_row(t, "Config file", v->config_path);
    if (v->kind == PMX_VPN_WIREGUARD) {
        kv_row(t, "Interface address", v->address);
        kv_row(t, "AllowedIPs", v->allowed_ips);
        kv_row(t, "Peer public key", v->peer_public_key);
    } else {
        kv_row(t, "Device", v->dev);
        kv_row(t, "Cipher", v->cipher);
        kv_row(t, "Auth digest", v->auth_digest);
    }
    kv_row(t, "DNS", v->dns);
    if (v->mtu > 0) {
        char mb[32];
        snprintf(mb, sizeof(mb), "%d", v->mtu);
        kv_row(t, "MTU", mb);
    }

    gui_vspace(8 * s);
    gui_field_label("Credentials in the config file");
    if (v->has_private_key) {
        gui_badge("private key", gui_theme_u32a(t->ok, 0.18f), gui_theme_u32(t->ok));
        igSameLine(0, 6 * s);
    }
    if (v->has_preshared_key) {
        gui_badge("preshared key", gui_theme_u32a(t->ok, 0.18f),
                  gui_theme_u32(t->ok));
        igSameLine(0, 6 * s);
    }
    if (v->has_inline_secrets) {
        gui_badge("inline secrets", gui_theme_u32a(t->ok, 0.18f),
                  gui_theme_u32(t->ok));
        igSameLine(0, 6 * s);
    }
    if (v->requires_user_pass) {
        gui_badge("asks for user/pass", gui_theme_u32a(t->warn, 0.18f),
                  gui_theme_u32(t->warn));
        igSameLine(0, 6 * s);
    }
    igNewLine();
    igTextDisabled("ProxiMight never copies key material — it stays in the file "
                   "above and is handed to the VPN client.");

    /* Validation. */
    char why[128];
    if (pmx_vpn_validate(v, why, sizeof(why)) != PMX_OK && why[0] != '\0') {
        gui_vspace(8 * s);
        gui_note(GUI_ICON_SHIELD, why, t->warn);
    }

    gui_vspace(12 * s);
    if (gui_danger_button("Remove tunnel", GUI_ICON_TRASH)) {
        gui_app_request_delete(app, 3, v->id, v->label);
    }
}

void panel_vpn(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    gui_note(GUI_ICON_LOCK,
             "A VPN is the overarching tunnel: your proxy rules ride inside it. "
             "ProxiMight reads OpenVPN (.ovpn) and WireGuard (.conf) files so it "
             "can allowlist the tunnel endpoint in lockdown and trace the path to "
             "it. Bringing the link up still belongs to the OpenVPN / WireGuard "
             "client — ProxiMight does not implement tunnel crypto.",
             t->accent);
    gui_vspace(12 * s);

    /* ---- vendor client status ---- */
    if (gui_card_begin("##vpnclients", 0)) {
        gui_section_header(GUI_ICON_GEAR, "VPN clients",
                           "ProxiMight drives these; it does not implement "
                           "tunnel crypto. Install them normally — they are not "
                           "bundled.");
        gui_vspace(8 * s);

        struct {
            pmx_vpn_kind kind;
            const char *name;
            char *override_buf;
            size_t override_cap;
            const char *install;
        } clients[2] = {
            {PMX_VPN_WIREGUARD, "WireGuard", pf->settings.wireguard_path,
             sizeof(pf->settings.wireguard_path),
             "winget install --id WireGuard.WireGuard -e"},
            {PMX_VPN_OPENVPN, "OpenVPN (Community)", pf->settings.openvpn_path,
             sizeof(pf->settings.openvpn_path),
             "winget install --id OpenVPNTechnologies.OpenVPN -e"},
        };

        for (int i = 0; i < 2; i++) {
            igPushID_Int(i + 900);
            pmx_vpn_client c;
            pmx_vpn_client_detect(clients[i].kind, clients[i].override_buf, &c);

            gui_status_pill(clients[i].name, c.found ? t->ok : t->text_faint);
            igSameLine(0, 10 * s);
            if (c.found) {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_dim[0],
                                                        t->text_dim[1],
                                                        t->text_dim[2], 1));
                igTextUnformatted(c.path, NULL);
                igPopStyleColor(1);
            } else {
                igTextDisabled("not installed — %s", clients[i].install);
            }
            gui_vspace(2 * s);
            gui_field_label("Override path (blank = auto-detect)");
            gui_input_text("##clientpath", "e.g. C:\\Program Files\\...",
                           clients[i].override_buf, clients[i].override_cap,
                           false);
            gui_vspace(8 * s);
            igPopID();
        }

        /* Show exactly what would be run for the selected tunnel. */
        pmx_vpn *sel_for_cmd = pmx_profile_find_vpn(pf, app->sel_vpn);
        if (sel_for_cmd != NULL && sel_for_cmd->config_path[0] != '\0') {
            pmx_vpn_client c;
            pmx_vpn_client_detect(sel_for_cmd->kind,
                                  sel_for_cmd->kind == PMX_VPN_WIREGUARD
                                      ? pf->settings.wireguard_path
                                      : pf->settings.openvpn_path,
                                  &c);
            char cmd[PMX_MAX_PATH + 160];
            if (pmx_vpn_bringup_command(sel_for_cmd, &c, cmd, sizeof(cmd)) ==
                PMX_OK) {
                gui_field_label("Bring-up command for the selected tunnel "
                                "(this is exactly what Connect runs)");
                igPushStyleColor_Vec4(ImGuiCol_Text,
                                      v4(t->text_dim[0], t->text_dim[1],
                                         t->text_dim[2], 1));
                igTextWrapped("%s", cmd);
                igPopStyleColor(1);
            }
        }
        gui_card_end();
    }
    gui_vspace(12 * s);

    if (igBeginTable("##vpncols", 2, 0, v2(0, 0), 0)) {
        igTableSetupColumn("list", ImGuiTableColumnFlags_WidthStretch, 0.40f, 0);
        igTableSetupColumn("edit", ImGuiTableColumnFlags_WidthStretch, 0.60f, 0);
        igTableNextRow(0, 0);

        igTableSetColumnIndex(0);
        if (gui_card_begin("##vpnlist", 0)) {
            gui_section_header(GUI_ICON_LOCK, "VPN tunnels", NULL);
            gui_vspace(6 * s);
            if (gui_primary_button("Import config…", GUI_ICON_PLUS)) {
                char path[PMX_MAX_PATH];
                if (guix_open_file_dialog("Import a VPN configuration",
                                          "VPN configs", "*.ovpn;*.conf",
                                          path, sizeof(path))) {
                    pmx_vpn *nv = NULL;
                    pmx_status st = pmx_profile_import_vpn(pf, path, &nv);
                    if (st == PMX_OK && nv != NULL) {
                        app->sel_vpn = nv->id;
                        char msg[128];
                        snprintf(msg, sizeof(msg), "Imported %s tunnel '%s'.",
                                 pmx_vpn_kind_str(nv->kind), nv->label);
                        gui_app_status(app, msg);
                    } else {
                        gui_app_status(app,
                                       "Could not parse that file as an OpenVPN "
                                       "or WireGuard config.");
                    }
                }
            }
            gui_vspace(6 * s);
            if (pf->vpn_count == 0) {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("No tunnels imported yet.");
                igPopStyleColor(1);
            }
            for (size_t i = 0; i < pf->vpn_count; i++) {
                if (vpn_row(app, &pf->vpns[i])) {
                    app->sel_vpn = pf->vpns[i].id;
                }
                gui_vspace(2 * s);
            }
            gui_card_end();
        }

        igTableSetColumnIndex(1);
        if (gui_card_begin("##vpnedit", 0)) {
            pmx_vpn *sel = pmx_profile_find_vpn(pf, app->sel_vpn);
            if (sel != NULL) {
                vpn_editor(app, sel);
            } else {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("Import a .ovpn or .conf file, or select a tunnel "
                              "to inspect what ProxiMight parsed from it.");
                igPopStyleColor(1);
            }
            gui_card_end();
        }
        igEndTable();
    }
}
