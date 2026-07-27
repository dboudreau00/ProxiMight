#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

void panel_checker(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);
    pmx_checker *chk = pmx_engine_checker(app->engine);

    if (gui_card_begin("##checkcard", 0)) {
        gui_section_header(GUI_ICON_REFRESH, "Proxy checker",
                           "Reachability, handshake and latency for each proxy.");
        gui_vspace(8 * s);

        if (gui_primary_button("Check all enabled", GUI_ICON_REFRESH)) {
            pmx_checker_set_opts(chk, &pf->settings.check);
            for (size_t i = 0; i < pf->proxy_count; i++) {
                if (pf->proxies[i].enabled) {
                    pmx_checker_submit(chk, &pf->proxies[i]);
                }
            }
            gui_app_status(app, "Checking all enabled proxies…");
        }
        igSameLine(0, 16 * s);
        igTextUnformatted("Ping", NULL);
        igSameLine(0, 8 * s);
        if (gui_toggle("##pingtoggle", &pf->settings.check.measure_ping)) {
            pmx_checker_set_opts(chk, &pf->settings.check);
        }
        igSameLine(0, 16 * s);
        igTextUnformatted("Measure egress IP", NULL);
        igSameLine(0, 8 * s);
        if (gui_toggle("##egress", &pf->settings.check.measure_egress_ip)) {
            pmx_checker_set_opts(chk, &pf->settings.check);
        }
        igSameLine(0, 16 * s);
        {
            size_t pend = pmx_checker_pending(chk);
            if (pend > 0) {
                char pb[48];
                snprintf(pb, sizeof(pb), "%zu in progress…", pend);
                igTextDisabled("%s", pb);
            }
        }
        gui_vspace(8 * s);

        if (pf->settings.check.measure_egress_ip) {
            gui_note(GUI_ICON_GLOBE,
                     "Egress-IP measurement makes a real outbound request through "
                     "each proxy to a third-party IP-echo service. That reveals "
                     "your use of the proxy to that service — off by default.",
                     t->warn);
            gui_vspace(8 * s);
        }

        ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                             ImGuiTableFlags_SizingStretchProp;
        if (igBeginTable("##checktbl", 7, tf, v2(0, 0), 0)) {
            igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 20 * s, 0);
            igTableSetupColumn("Proxy", ImGuiTableColumnFlags_WidthStretch, 0.24f, 0);
            igTableSetupColumn("Endpoint", ImGuiTableColumnFlags_WidthStretch, 0.22f, 0);
            igTableSetupColumn("Ping", ImGuiTableColumnFlags_WidthFixed, 70 * s, 0);
            igTableSetupColumn("Handshake", ImGuiTableColumnFlags_WidthFixed, 84 * s, 0);
            igTableSetupColumn("Result", ImGuiTableColumnFlags_WidthStretch, 0.32f, 0);
            igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 44 * s, 0);
            igTableHeadersRow();

            for (size_t i = 0; i < pf->proxy_count; i++) {
                pmx_proxy *p = &pf->proxies[i];
                const pmx_check_result *r = gui_app_find_check(app, p->id, -1);
                igTableNextRow(0, 0);
                igPushID_Int((int)i + 1);

                igTableSetColumnIndex(0);
                const float *dc = t->text_faint;
                if (r != NULL) {
                    dc = (r->status == PMX_OK) ? t->ok
                         : r->reachable        ? t->warn
                                               : t->danger;
                }
                float cx = 0, cy = 0;
                guix_cursor_screen(&cx, &cy);
                guix_draw_circle_filled(cx + 6 * s, cy + igGetTextLineHeight() * 0.5f,
                                        5 * s, gui_theme_u32(dc), 16);
                igDummy(v2(14 * s, igGetTextLineHeight()));

                igTableSetColumnIndex(1);
                igTextUnformatted(p->label, NULL);
                igTableSetColumnIndex(2);
                char ep[300];
                snprintf(ep, sizeof(ep), "%s:%u", p->host, (unsigned)p->port);
                igTextUnformatted(ep, NULL);

                /* ICMP round-trip: raw network distance to the box. */
                igTableSetColumnIndex(3);
                if (r != NULL && r->ping_ms >= 0) {
                    char pb2[24];
                    snprintf(pb2, sizeof(pb2), "%d ms", r->ping_ms);
                    igTextUnformatted(pb2, NULL);
                } else {
                    igTextDisabled("—");
                }

                /* TCP connect + proxy handshake: what the proxy itself costs. */
                igTableSetColumnIndex(4);
                if (r != NULL && r->latency_ms >= 0) {
                    char lb[24];
                    snprintf(lb, sizeof(lb), "%d ms", r->latency_ms);
                    igTextUnformatted(lb, NULL);
                } else {
                    igTextDisabled("—");
                }

                igTableSetColumnIndex(5);
                if (r != NULL) {
                    igTextUnformatted(r->message, NULL);
                    if (r->egress_ip[0]) {
                        igSameLine(0, 6 * s);
                        char eg[80];
                        snprintf(eg, sizeof(eg), "(%s)", r->egress_ip);
                        igTextDisabled("%s", eg);
                    }
                } else {
                    igTextDisabled("not tested");
                }

                igTableSetColumnIndex(6);
                if (gui_icon_button("##test", GUI_ICON_PLAY, "Test this proxy",
                                    GUI_BTN_GHOST)) {
                    pmx_checker_set_opts(chk, &pf->settings.check);
                    pmx_checker_submit(chk, p);
                }
                igPopID();
            }
            igEndTable();
        }

        if (pf->proxy_count == 0) {
            igPushStyleColor_Vec4(ImGuiCol_Text,
                                  v4(t->text_faint[0], t->text_faint[1], t->text_faint[2], 1));
            igTextWrapped("Add proxies first, then check them here.");
            igPopStyleColor(1);
        }
        gui_card_end();
    }

    gui_vspace(12 * s);

    /* ---- network path (MTR) ---- */
    if (gui_card_begin("##pathcard", 0)) {
        gui_section_header(GUI_ICON_ROUTE, "Network path",
                           "Per-hop latency and packet loss, like mtr.");
        gui_vspace(8 * s);

        bool running = (app->mtr_job != NULL && !app->mtr_have_result);

        igSetNextItemWidth(300 * s);
        igInputTextWithHint("##pathtarget", "host or IP  (e.g. 1.1.1.1)",
                            app->mtr_target, sizeof(app->mtr_target), 0, NULL,
                            NULL);
        igSameLine(0, 8 * s);
        if (running) {
            char pb[64];
            snprintf(pb, sizeof(pb), "Tracing… hop %d",
                     pmx_mtr_progress(app->mtr_job));
            igTextDisabled("%s", pb);
        } else {
            if (gui_primary_button("Trace path", GUI_ICON_ROUTE) &&
                app->mtr_target[0] != '\0') {
                gui_app_start_path_scan(app, app->mtr_target);
            }
            if (pf->proxy_count > 0) {
                igSameLine(0, 8 * s);
                if (gui_secondary_button("Trace first proxy", GUI_ICON_LINK)) {
                    gui_app_start_path_scan(app, pf->proxies[0].host);
                }
            }
        }

        gui_vspace(8 * s);
        gui_note(GUI_ICON_GLOBE,
                 "ICMP measures the path from THIS machine. It cannot travel "
                 "through a SOCKS/HTTP proxy, so this shows your route to the "
                 "host — not the route your traffic takes after the proxy.",
                 t->accent);
        gui_vspace(8 * s);

        if (app->mtr_have_result) {
            const pmx_mtr_result *m = &app->mtr_result;
            char hdr[256];
            snprintf(hdr, sizeof(hdr), "%s (%s) — %zu hop%s%s", m->target,
                     m->target_addr, m->hop_count, m->hop_count == 1 ? "" : "s",
                     m->reached ? "" : ", destination did not answer");
            igPushStyleColor_Vec4(ImGuiCol_Text,
                                  v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
            igTextWrapped("%s", hdr);
            igPopStyleColor(1);
            gui_vspace(6 * s);

            ImGuiTableFlags ptf = ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_BordersInnerH |
                                  ImGuiTableFlags_SizingStretchProp;
            if (igBeginTable("##hops", 7, ptf, v2(0, 0), 0)) {
                igTableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30 * s, 0);
                igTableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.44f, 0);
                igTableSetupColumn("Loss", ImGuiTableColumnFlags_WidthFixed, 62 * s, 0);
                igTableSetupColumn("Sent", ImGuiTableColumnFlags_WidthFixed, 48 * s, 0);
                igTableSetupColumn("Best", ImGuiTableColumnFlags_WidthFixed, 62 * s, 0);
                igTableSetupColumn("Avg", ImGuiTableColumnFlags_WidthFixed, 62 * s, 0);
                igTableSetupColumn("Worst", ImGuiTableColumnFlags_WidthFixed, 62 * s, 0);
                igTableHeadersRow();

                for (size_t i = 0; i < m->hop_count; i++) {
                    const pmx_hop *h = &m->hops[i];
                    igTableNextRow(0, 0);

                    igTableSetColumnIndex(0);
                    char nb[8];
                    snprintf(nb, sizeof(nb), "%d", h->ttl);
                    igTextUnformatted(nb, NULL);

                    igTableSetColumnIndex(1);
                    if (h->addr[0] == '\0') {
                        igTextDisabled("* * *  (no reply)");
                    } else if (h->name[0] != '\0') {
                        char hb[320];
                        snprintf(hb, sizeof(hb), "%s (%s)", h->name, h->addr);
                        igTextUnformatted(hb, NULL);
                    } else {
                        igTextUnformatted(h->addr, NULL);
                    }
                    if (h->is_dest) {
                        igSameLine(0, 6 * s);
                        gui_badge("target", gui_theme_u32a(t->ok, 0.18f),
                                  gui_theme_u32(t->ok));
                    }

                    igTableSetColumnIndex(2);
                    {
                        char lb[16];
                        snprintf(lb, sizeof(lb), "%.0f%%", h->loss_pct);
                        const float *lc = (h->loss_pct >= 50.0) ? t->danger
                                          : (h->loss_pct > 0.0) ? t->warn
                                                                : t->text_dim;
                        igPushStyleColor_Vec4(ImGuiCol_Text,
                                              v4(lc[0], lc[1], lc[2], 1));
                        igTextUnformatted(lb, NULL);
                        igPopStyleColor(1);
                    }

                    igTableSetColumnIndex(3);
                    char sb[16];
                    snprintf(sb, sizeof(sb), "%d", h->sent);
                    igTextUnformatted(sb, NULL);

                    char tb[16];
                    igTableSetColumnIndex(4);
                    if (h->best_ms >= 0) {
                        snprintf(tb, sizeof(tb), "%d", h->best_ms);
                        igTextUnformatted(tb, NULL);
                    } else {
                        igTextDisabled("—");
                    }
                    igTableSetColumnIndex(5);
                    if (h->recv > 0) {
                        snprintf(tb, sizeof(tb), "%.1f", h->avg_ms);
                        igTextUnformatted(tb, NULL);
                    } else {
                        igTextDisabled("—");
                    }
                    igTableSetColumnIndex(6);
                    if (h->worst_ms >= 0) {
                        snprintf(tb, sizeof(tb), "%d", h->worst_ms);
                        igTextUnformatted(tb, NULL);
                    } else {
                        igTextDisabled("—");
                    }
                }
                igEndTable();
            }
        } else if (!running) {
            igPushStyleColor_Vec4(ImGuiCol_Text,
                                  v4(t->text_faint[0], t->text_faint[1],
                                     t->text_faint[2], 1));
            igTextWrapped("No path traced yet.");
            igPopStyleColor(1);
        }
        gui_card_end();
    }
}
