#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static const char *const kProxyTypes[] = {"SOCKS5", "SOCKS4", "SOCKS4a", "HTTP",
                                           "HTTPS"};

static const float *proxy_status_color(gui_app *app, const pmx_proxy *p) {
    const gui_theme *t = &app->theme;
    if (!p->enabled) {
        return t->text_faint;
    }
    const pmx_check_result *r = gui_app_find_check(app, p->id, -1);
    if (r == NULL) {
        return t->text_faint;
    }
    if (r->status == PMX_OK) {
        return t->ok;
    }
    if (r->reachable) {
        return t->warn;
    }
    return t->danger;
}

static bool proxy_row(gui_app *app, const pmx_proxy *p) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    float availw = 0;
    guix_content_avail(&availw, NULL);
    float h = 46.0f * s;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    char id[48];
    snprintf(id, sizeof(id), "##pxrow%llu", (unsigned long long)p->id);
    bool pressed = igInvisibleButton(id, v2(availw, h), 0);
    bool hovered = igIsItemHovered(0);
    bool selected = (app->sel_proxy == p->id);

    unsigned bg = selected ? gui_theme_u32a(t->accent, t->dark ? 0.18f : 0.12f)
                           : (hovered ? gui_theme_u32(t->surface2) : 0);
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + availw, y0 + h, bg, 8.0f * s);
    }
    if (selected) {
        guix_draw_rect_filled(x0, y0 + 8 * s, x0 + 3.0f * s, y0 + h - 8 * s,
                              gui_theme_u32(t->accent), 2.0f * s);
    }
    guix_draw_circle_filled(x0 + 16 * s, y0 + h * 0.5f, 5.0f * s,
                            gui_theme_u32(proxy_status_color(app, p)), 16);
    guix_draw_text(x0 + 30 * s, y0 + 8 * s, gui_theme_u32(t->text), p->label);
    char sub[320];
    snprintf(sub, sizeof(sub), "%s  •  %s:%u", pmx_proxy_type_str(p->type), p->host,
             (unsigned)p->port);
    guix_draw_text(x0 + 30 * s, y0 + h - 20 * s, gui_theme_u32(t->text_dim), sub);
    if (!p->enabled) {
        float tw = 0, th = 0;
        guix_calc_text("disabled", &tw, &th);
        guix_draw_text(x0 + availw - tw - 12 * s, y0 + 8 * s,
                       gui_theme_u32(t->text_faint), "disabled");
    }
    return pressed;
}

static void proxy_editor(gui_app *app, pmx_proxy *p) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    gui_section_header(GUI_ICON_LINK, p->label[0] ? p->label : "Proxy", NULL);
    gui_vspace(8 * s);

    gui_field_label("Label");
    gui_input_text("##pxlabel", "e.g. Home SOCKS", p->label, sizeof(p->label),
                   false);
    gui_vspace(6 * s);

    gui_field_label("Type");
    int type = (int)p->type;
    if (gui_combo("##pxtype", &type, kProxyTypes, 5)) {
        p->type = (pmx_proxy_type)type;
    }
    gui_vspace(6 * s);

    if (igBeginTable("##hostport", 2, 0, v2(0, 0), 0)) {
        igTableSetupColumn("h", ImGuiTableColumnFlags_WidthStretch, 0.7f, 0);
        igTableSetupColumn("p", ImGuiTableColumnFlags_WidthStretch, 0.3f, 0);
        igTableNextRow(0, 0);
        igTableSetColumnIndex(0);
        gui_field_label("Host");
        gui_input_text("##pxhost", "host or IP", p->host, sizeof(p->host), false);
        igTableSetColumnIndex(1);
        gui_field_label("Port");
        int port = (int)p->port;
        if (gui_input_int("##pxport", &port, 1, 65535)) {
            p->port = (pmx_port)port;
        }
        igEndTable();
    }
    gui_vspace(8 * s);

    igTextUnformatted("Requires authentication", NULL);
    igSameLine(0, 10 * s);
    gui_toggle("##pxauth", &p->use_auth);
    if (p->use_auth) {
        gui_vspace(4 * s);
        gui_field_label("Username");
        gui_input_text("##pxuser", NULL, p->username, sizeof(p->username), false);
        gui_vspace(4 * s);
        gui_field_label("Password");
        gui_input_text("##pxpass", NULL, p->password, sizeof(p->password), true);
    }
    gui_vspace(8 * s);

    igTextUnformatted("Enabled", NULL);
    igSameLine(0, 10 * s);
    gui_toggle("##pxenabled", &p->enabled);
    gui_vspace(10 * s);

    /* Validation hint. */
    char why[96];
    pmx_status vst = pmx_proxy_validate(p, why, sizeof(why));
    if (vst != PMX_OK && why[0]) {
        gui_note(GUI_ICON_SHIELD, why, t->warn);
        gui_vspace(8 * s);
    }

    if (gui_primary_button("Test", GUI_ICON_REFRESH)) {
        pmx_checker_submit(pmx_engine_checker(app->engine), p);
        gui_app_status(app, "Testing proxy…");
    }
    igSameLine(0, 8 * s);
    if (gui_danger_button("Delete", GUI_ICON_TRASH)) {
        gui_app_request_delete(app, 0, p->id, p->label);
    }

    /* Latest result. */
    const pmx_check_result *r = gui_app_find_check(app, p->id, -1);
    if (r != NULL) {
        gui_vspace(10 * s);
        const float *c = (r->status == PMX_OK) ? t->ok
                          : r->reachable       ? t->warn
                                               : t->danger;
        gui_status_pill(r->message, c);
        if (r->egress_ip[0]) {
            gui_vspace(2 * s);
            char eg[96];
            snprintf(eg, sizeof(eg), "egress IP: %s", r->egress_ip);
            igPushStyleColor_Vec4(ImGuiCol_Text,
                                  v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
            igTextUnformatted(eg, NULL);
            igPopStyleColor(1);
        }
    }
}

void panel_proxies(gui_app *app) {
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    if (igBeginTable("##pxcols", 2, ImGuiTableFlags_None, v2(0, 0), 0)) {
        igTableSetupColumn("list", ImGuiTableColumnFlags_WidthStretch, 0.40f, 0);
        igTableSetupColumn("edit", ImGuiTableColumnFlags_WidthStretch, 0.60f, 0);
        igTableNextRow(0, 0);

        igTableSetColumnIndex(0);
        if (gui_card_begin("##pxlist", 0)) {
            gui_section_header(GUI_ICON_LINK, "Proxy servers", NULL);
            igSameLine(0, 10 * s);
            {
                float aw = 0;
                guix_content_avail(&aw, NULL);
                float bw = 70 * s;
                igDummy(v2(aw - bw, 1));
                igSameLine(0, 0);
            }
            if (gui_primary_button("Add", GUI_ICON_PLUS)) {
                pmx_proxy *np = pmx_profile_add_proxy(pf);
                if (np != NULL) {
                    app->sel_proxy = np->id;
                }
            }
            gui_vspace(6 * s);
            if (pf->proxy_count == 0) {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(app->theme.text_faint[0],
                                                        app->theme.text_faint[1],
                                                        app->theme.text_faint[2], 1));
                igTextWrapped("No proxies yet. Click Add to create one.");
                igPopStyleColor(1);
            }
            for (size_t i = 0; i < pf->proxy_count; i++) {
                if (proxy_row(app, &pf->proxies[i])) {
                    app->sel_proxy = pf->proxies[i].id;
                }
                gui_vspace(2 * s);
            }
            gui_card_end();
        }

        igTableSetColumnIndex(1);
        if (gui_card_begin("##pxedit", 0)) {
            pmx_proxy *sel = pmx_profile_find_proxy(pf, app->sel_proxy);
            if (sel != NULL) {
                proxy_editor(app, sel);
            } else {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(app->theme.text_faint[0],
                                                        app->theme.text_faint[1],
                                                        app->theme.text_faint[2], 1));
                igTextWrapped("Select a proxy on the left, or add one, to edit its "
                              "settings.");
                igPopStyleColor(1);
            }
            gui_card_end();
        }
        igEndTable();
    }
}
