#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static const char *const kChainModes[] = {"Sequential (through all hops)",
                                           "Redundancy (fail over to next)"};

static bool chain_row(gui_app *app, const pmx_chain *c) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    float availw = 0;
    guix_content_avail(&availw, NULL);
    float h = 46.0f * s;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    char id[48];
    snprintf(id, sizeof(id), "##chrow%llu", (unsigned long long)c->id);
    bool pressed = igInvisibleButton(id, v2(availw, h), 0);
    bool hovered = igIsItemHovered(0);
    bool selected = (app->sel_chain == c->id);
    unsigned bg = selected ? gui_theme_u32a(t->accent, t->dark ? 0.18f : 0.12f)
                           : (hovered ? gui_theme_u32(t->surface2) : 0);
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + availw, y0 + h, bg, 8 * s);
    }
    if (selected) {
        guix_draw_rect_filled(x0, y0 + 8 * s, x0 + 3 * s, y0 + h - 8 * s,
                              gui_theme_u32(t->accent), 2 * s);
    }
    gui_icon(GUI_ICON_CHAIN, x0 + 10 * s, y0 + (h - 22 * s) * 0.5f, 22 * s,
             gui_theme_u32(selected ? t->accent : t->text_dim));
    guix_draw_text(x0 + 40 * s, y0 + 8 * s, gui_theme_u32(t->text), c->label);
    char sub[64];
    snprintf(sub, sizeof(sub), "%s • %zu hop%s", pmx_chain_mode_str(c->mode),
             c->hop_count, c->hop_count == 1 ? "" : "s");
    guix_draw_text(x0 + 40 * s, y0 + h - 20 * s, gui_theme_u32(t->text_dim), sub);
    return pressed;
}

static void chain_editor(gui_app *app, pmx_chain *c) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    gui_section_header(GUI_ICON_CHAIN, c->label[0] ? c->label : "Chain", NULL);
    gui_vspace(8 * s);
    gui_field_label("Label");
    gui_input_text("##chlabel", "Chain name", c->label, sizeof(c->label), false);
    gui_vspace(6 * s);
    gui_field_label("Mode");
    int mode = (int)c->mode;
    if (gui_combo("##chmode", &mode, kChainModes, 2)) {
        c->mode = (pmx_chain_mode)mode;
    }
    gui_vspace(4 * s);
    igTextUnformatted("Enabled", NULL);
    igSameLine(0, 10 * s);
    gui_toggle("##chen", &c->enabled);
    gui_vspace(10 * s);

    gui_field_label("Hops");
    if (c->hop_count == 0) {
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_faint[0], t->text_faint[1], t->text_faint[2], 1));
        igTextWrapped("No hops yet. Add a proxy below.");
        igPopStyleColor(1);
    }
    int remove_hop = -1, mv_from = -1, mv_to = -1;
    for (size_t h = 0; h < c->hop_count; h++) {
        igPushID_Int((int)h + 1);
        const pmx_proxy *p = pmx_profile_find_proxy_c(pf, c->hops[h]);
        char line[128];
        snprintf(line, sizeof(line), "%zu.  %s", h + 1,
                 p ? p->label : "(missing proxy)");

        /* per-hop status from cache */
        const pmx_check_result *r = gui_app_find_check(app, c->hops[h], (int)h);
        const float *dotc = t->text_faint;
        if (r != NULL) {
            dotc = (r->status == PMX_OK) ? t->ok : (r->reachable ? t->warn : t->danger);
        }
        float cx = 0, cy = 0;
        guix_cursor_screen(&cx, &cy);
        guix_draw_circle_filled(cx + 5 * s, cy + igGetTextLineHeight() * 0.5f, 5 * s,
                                gui_theme_u32(dotc), 16);
        igDummy(v2(16 * s, 0));
        igSameLine(0, 0);
        igTextUnformatted(line, NULL);

        igSameLine(0, 10 * s);
        {
            float aw = 0;
            guix_content_avail(&aw, NULL);
            igDummy(v2(aw - 108 * s, 1));
            igSameLine(0, 0);
        }
        if (gui_icon_button("##hup", GUI_ICON_UP, "Move up", GUI_BTN_GHOST) && h > 0) {
            mv_from = (int)h;
            mv_to = (int)h - 1;
        }
        igSameLine(0, 2 * s);
        if (gui_icon_button("##hdn", GUI_ICON_DOWN, "Move down", GUI_BTN_GHOST) &&
            h + 1 < c->hop_count) {
            mv_from = (int)h;
            mv_to = (int)h + 1;
        }
        igSameLine(0, 2 * s);
        if (gui_icon_button("##hrm", GUI_ICON_TRASH, "Remove hop", GUI_BTN_DANGER)) {
            remove_hop = (int)h;
        }
        igPopID();
        gui_vspace(2 * s);
    }
    if (mv_from >= 0) {
        pmx_chain_move_hop(c, (size_t)mv_from, (size_t)mv_to);
    }
    if (remove_hop >= 0) {
        pmx_chain_remove_hop(c, (size_t)remove_hop);
    }

    gui_vspace(8 * s);
    /* Add hop. */
    if (pf->proxy_count > 0 && c->hop_count < PMX_MAX_CHAIN_HOPS) {
        static int add_idx = 0;
        const char *labels[257];
        pmx_id ids[257];
        int count = 0;
        for (size_t i = 0; i < pf->proxy_count && count < 256; i++) {
            labels[count] = pf->proxies[i].label;
            ids[count] = pf->proxies[i].id;
            count++;
        }
        if (add_idx >= count) {
            add_idx = 0;
        }
        igSetNextItemWidth(240 * s);
        igCombo_Str_arr("##addhop", &add_idx, labels, count, -1);
        igSameLine(0, 8 * s);
        if (gui_secondary_button("Add hop", GUI_ICON_PLUS)) {
            pmx_chain_add_hop(c, ids[add_idx]);
        }
    } else if (c->hop_count >= PMX_MAX_CHAIN_HOPS) {
        gui_note(GUI_ICON_CHAIN, "Maximum hops reached for this chain.", t->warn);
    }

    gui_vspace(12 * s);
    if (gui_primary_button("Test chain", GUI_ICON_REFRESH)) {
        pmx_checker_submit_chain(pmx_engine_checker(app->engine), c, pf->proxies,
                                 pf->proxy_count);
        gui_app_status(app, "Testing chain hops…");
    }
    igSameLine(0, 8 * s);
    if (gui_danger_button("Delete chain", GUI_ICON_TRASH)) {
        gui_app_request_delete(app, 2, c->id, c->label);
    }
}

void panel_chains(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    if (igBeginTable("##chcols", 2, 0, v2(0, 0), 0)) {
        igTableSetupColumn("list", ImGuiTableColumnFlags_WidthStretch, 0.40f, 0);
        igTableSetupColumn("edit", ImGuiTableColumnFlags_WidthStretch, 0.60f, 0);
        igTableNextRow(0, 0);

        igTableSetColumnIndex(0);
        if (gui_card_begin("##chlist", 0)) {
            gui_section_header(GUI_ICON_CHAIN, "Proxy chains", NULL);
            igSameLine(0, 10 * s);
            {
                float aw = 0;
                guix_content_avail(&aw, NULL);
                igDummy(v2(aw - 70 * s, 1));
                igSameLine(0, 0);
            }
            if (gui_primary_button("Add", GUI_ICON_PLUS)) {
                pmx_chain *nc = pmx_profile_add_chain(pf);
                if (nc != NULL) {
                    app->sel_chain = nc->id;
                }
            }
            gui_vspace(6 * s);
            if (pf->chain_count == 0) {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("No chains yet. A chain routes through several "
                              "proxies in sequence, or fails over between them.");
                igPopStyleColor(1);
            }
            for (size_t i = 0; i < pf->chain_count; i++) {
                if (chain_row(app, &pf->chains[i])) {
                    app->sel_chain = pf->chains[i].id;
                }
                gui_vspace(2 * s);
            }
            gui_card_end();
        }

        igTableSetColumnIndex(1);
        if (gui_card_begin("##chedit", 0)) {
            pmx_chain *sel = pmx_profile_find_chain(pf, app->sel_chain);
            if (sel != NULL) {
                chain_editor(app, sel);
            } else {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("Select a chain, or add one, to edit its hops.");
                igPopStyleColor(1);
            }
            gui_card_end();
        }
        igEndTable();
    }
}
