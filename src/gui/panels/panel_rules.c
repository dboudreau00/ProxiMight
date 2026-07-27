#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static const char *const kActions[] = {"Direct", "Proxy", "Block"};
static const char *const kTargetKinds[] = {"Single proxy", "Chain"};

static void action_badge(gui_app *app, pmx_action a) {
    const gui_theme *t = &app->theme;
    const float *c = t->text_dim;
    if (a == PMX_ACTION_DIRECT) c = t->ok;
    else if (a == PMX_ACTION_PROXY) c = t->accent;
    else if (a == PMX_ACTION_BLOCK) c = t->danger;
    gui_badge(pmx_action_str(a), gui_theme_u32a(c, 0.18f), gui_theme_u32(c));
}

/* Combo that picks a proxy or chain id; returns true if the selection changed. */
static bool target_selector(gui_app *app, pmx_rule *r) {
    pmx_profile *pf = pmx_engine_profile(app->engine);
    const char *labels[257];
    pmx_id ids[257];
    int count = 0;
    int current = 0;

    if (r->target_kind == PMX_TARGET_CHAIN) {
        for (size_t i = 0; i < pf->chain_count && count < 256; i++) {
            labels[count] = pf->chains[i].label;
            ids[count] = pf->chains[i].id;
            if (pf->chains[i].id == r->target_id) current = count;
            count++;
        }
    } else {
        for (size_t i = 0; i < pf->proxy_count && count < 256; i++) {
            labels[count] = pf->proxies[i].label;
            ids[count] = pf->proxies[i].id;
            if (pf->proxies[i].id == r->target_id) current = count;
            count++;
        }
    }
    if (count == 0) {
        gui_field_label(r->target_kind == PMX_TARGET_CHAIN
                            ? "No chains defined yet"
                            : "No proxies defined yet");
        return false;
    }
    if (gui_combo("##ruletarget", &current, labels, count)) {
        r->target_id = ids[current];
        return true;
    }
    if (r->target_id == PMX_ID_NONE) {
        r->target_id = ids[0];
    }
    return false;
}

static void rule_editor(gui_app *app, pmx_rule *r, size_t index) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    gui_section_header(GUI_ICON_LIST, "Edit rule", NULL);
    gui_vspace(8 * s);

    gui_field_label("Name");
    gui_input_text("##rname", "Rule name", r->name, sizeof(r->name), false);
    gui_vspace(4 * s);
    igTextUnformatted("Enabled", NULL);
    igSameLine(0, 10 * s);
    gui_toggle("##renabled", &r->enabled);
    gui_vspace(8 * s);

    gui_field_label("Applications  (; separated, * and ? wildcards)");
    gui_input_text("##rapp", "chrome.exe;*.exe   (blank = any)", r->app_pattern,
                   sizeof(r->app_pattern), false);
    gui_vspace(4 * s);
    gui_field_label("Target hosts");
    gui_input_text("##rhost", "10.*;192.168.*   (blank = any)",
                   r->host_pattern, sizeof(r->host_pattern), false);
    /* A name pattern can only match if the active backend reports host names.
     * The real Windows backend sees the connect AFTER the app resolved the
     * name, so it only has an IP — such a rule would silently never fire. */
    {
        pmx_engine_status est;
        memset(&est, 0, sizeof(est));
        pmx_engine_get_status(app->engine, &est);
        if (!est.backend_host_names &&
            pmx_host_pattern_needs_names(r->host_pattern)) {
            gui_vspace(4 * s);
            gui_note(GUI_ICON_SHIELD,
                     "This backend reports numeric addresses only — a host-name "
                     "pattern will NEVER match. Use IP patterns (e.g. 10.*).",
                     t->warn);
        }
    }
    gui_vspace(4 * s);
    gui_field_label("Ports");
    gui_input_text("##rports", "80,443,8000-8080   (blank = any)", r->port_spec,
                   sizeof(r->port_spec), false);
    if (pmx_port_spec_validate(r->port_spec) != PMX_OK) {
        gui_vspace(4 * s);
        gui_note(GUI_ICON_SHIELD, "Port spec looks invalid — use e.g. 80,443,1000-2000",
                 t->warn);
    }
    gui_vspace(8 * s);

    gui_field_label("Action");
    int action = (int)r->action;
    if (gui_combo("##raction", &action, kActions, 3)) {
        r->action = (pmx_action)action;
        if (r->action != PMX_ACTION_PROXY) {
            r->target_kind = PMX_TARGET_NONE;
        } else if (r->target_kind == PMX_TARGET_NONE) {
            r->target_kind = PMX_TARGET_PROXY;
        }
    }

    if (r->action == PMX_ACTION_PROXY) {
        /* Repair unconditionally, not just when the combo above CHANGES: a rule
         * that is already Proxy never fires that callback, so target_kind could
         * sit at NONE while the picker below happily shows a selected proxy —
         * and the engine would resolve the rule to zero hops (un-routable). */
        if (r->target_kind == PMX_TARGET_NONE) {
            r->target_kind = PMX_TARGET_PROXY;
        }
        gui_vspace(6 * s);
        gui_field_label("Route via");
        int kind = (r->target_kind == PMX_TARGET_CHAIN) ? 1 : 0;
        if (gui_combo("##rtkind", &kind, kTargetKinds, 2)) {
            r->target_kind = (kind == 1) ? PMX_TARGET_CHAIN : PMX_TARGET_PROXY;
            r->target_id = PMX_ID_NONE;
        }
        gui_vspace(4 * s);
        target_selector(app, r);
    }

    gui_vspace(12 * s);
    if (gui_secondary_button("Move up", GUI_ICON_UP) && index > 0) {
        pmx_profile_move_rule(pf, index, index - 1);
    }
    igSameLine(0, 8 * s);
    if (gui_secondary_button("Move down", GUI_ICON_DOWN) &&
        index + 1 < pf->rule_count) {
        pmx_profile_move_rule(pf, index, index + 1);
    }
    igSameLine(0, 8 * s);
    if (gui_danger_button("Delete", GUI_ICON_TRASH)) {
        gui_app_request_delete(app, 1, r->id, r->name);
    }
}

void panel_rules(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);

    if (gui_card_begin("##rulescard", 0)) {
        gui_section_header(GUI_ICON_LIST, "Proxification rules",
                           "First matching enabled rule wins; drag the handle to "
                           "reorder.");
        igSameLine(0, 10 * s);
        {
            float aw = 0;
            guix_content_avail(&aw, NULL);
            igDummy(v2(aw - 90 * s, 1));
            igSameLine(0, 0);
        }
        if (gui_primary_button("Add rule", GUI_ICON_PLUS)) {
            pmx_rule *nr = pmx_profile_add_rule(pf);
            if (nr != NULL) {
                app->sel_proxy = nr->id; /* not used; keep sel below */
            }
        }
        gui_vspace(6 * s);

        int move_from = -1, move_to = -1;
        static pmx_id sel_rule = 0;

        ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                             ImGuiTableFlags_SizingStretchProp;
        if (igBeginTable("##rulestbl", 8, tf, v2(0, 0), 0)) {
            igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 26 * s, 0);
            igTableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 44 * s, 0);
            igTableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.22f, 0);
            igTableSetupColumn("Applications", ImGuiTableColumnFlags_WidthStretch, 0.22f, 0);
            igTableSetupColumn("Hosts", ImGuiTableColumnFlags_WidthStretch, 0.18f, 0);
            igTableSetupColumn("Ports", ImGuiTableColumnFlags_WidthStretch, 0.12f, 0);
            igTableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 80 * s, 0);
            igTableSetupColumn("Via", ImGuiTableColumnFlags_WidthStretch, 0.16f, 0);
            igTableHeadersRow();

            for (size_t i = 0; i < pf->rule_count; i++) {
                pmx_rule *r = &pf->rules[i];
                igTableNextRow(0, 0);
                igPushID_Int((int)i);

                /* drag handle */
                igTableSetColumnIndex(0);
                igSelectable_Bool("##grip", false, 0, v2(22 * s, 0));
                {
                    float ix0 = 0, iy0 = 0, ix1 = 0, iy1 = 0;
                    guix_item_min(&ix0, &iy0);
                    guix_item_max(&ix1, &iy1);
                    gui_icon(GUI_ICON_GRIP, ix0 + (ix1 - ix0 - 12 * s) * 0.5f,
                             iy0 + (iy1 - iy0 - 12 * s) * 0.5f, 12 * s,
                             gui_theme_u32(t->text_faint));
                }
                if (igBeginDragDropSource(0)) {
                    int idx = (int)i;
                    igSetDragDropPayload("PMX_RULE", &idx, sizeof(int), 0);
                    igTextUnformatted(r->name, NULL);
                    igEndDragDropSource();
                }
                if (igBeginDragDropTarget()) {
                    const ImGuiPayload *pl = igAcceptDragDropPayload("PMX_RULE", 0);
                    if (pl != NULL && pl->Data != NULL) {
                        move_from = *(const int *)pl->Data;
                        move_to = (int)i;
                    }
                    igEndDragDropTarget();
                }

                igTableSetColumnIndex(1);
                gui_toggle("##ren", &r->enabled);

                igTableSetColumnIndex(2);
                if (igSelectable_Bool(r->name[0] ? r->name : "(unnamed)",
                                      sel_rule == r->id,
                                      ImGuiSelectableFlags_SpanAllColumns, v2(0, 0))) {
                    sel_rule = r->id;
                }

                igTableSetColumnIndex(3);
                igTextUnformatted(r->app_pattern[0] ? r->app_pattern : "any", NULL);
                igTableSetColumnIndex(4);
                igTextUnformatted(r->host_pattern[0] ? r->host_pattern : "any", NULL);
                igTableSetColumnIndex(5);
                igTextUnformatted(r->port_spec[0] ? r->port_spec : "any", NULL);

                igTableSetColumnIndex(6);
                action_badge(app, r->action);

                igTableSetColumnIndex(7);
                if (r->action == PMX_ACTION_PROXY) {
                    char lbl[80];
                    pmx_profile_target_label(pf, r->target_kind, r->target_id, lbl,
                                             sizeof(lbl));
                    igTextUnformatted(lbl, NULL);
                } else {
                    igTextDisabled("—");
                }
                igPopID();
            }
            /* The catch-all default rule (read-only presentation). */
            igTableNextRow(0, 0);
            igTableSetColumnIndex(2);
            igTextDisabled("Default");
            igTableSetColumnIndex(3);
            igTextDisabled("(everything else)");
            igTableSetColumnIndex(6);
            action_badge(app, pf->default_rule.action);
            igEndTable();
        }

        if (move_from >= 0 && move_to >= 0 && move_from != move_to) {
            pmx_profile_move_rule(pf, (size_t)move_from, (size_t)move_to);
        }
        gui_card_end();

        gui_vspace(12 * s);
        if (gui_card_begin("##ruleedit", 0)) {
            pmx_rule *sel = NULL;
            size_t sel_index = 0;
            for (size_t i = 0; i < pf->rule_count; i++) {
                if (pf->rules[i].id == sel_rule) {
                    sel = &pf->rules[i];
                    sel_index = i;
                    break;
                }
            }
            if (sel != NULL) {
                rule_editor(app, sel, sel_index);
            } else {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("Select a rule above to edit it.");
                igPopStyleColor(1);
            }
            gui_card_end();
        }
    }
}
