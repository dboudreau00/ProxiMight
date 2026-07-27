#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static void verdict_color(const gui_theme *t, pmx_verdict v, const float **c) {
    switch (v) {
    case PMX_VERDICT_PROXY:  *c = t->accent; break;
    case PMX_VERDICT_DIRECT: *c = t->ok; break;
    case PMX_VERDICT_BLOCK:  *c = t->danger; break;
    default:                 *c = t->text_dim; break;
    }
}

static void tab_connections(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    pmx_conn_event evs[512];
    size_t n = pmx_engine_recent_events(app->engine, evs, 512);

    char cnt[48];
    snprintf(cnt, sizeof(cnt), "%zu event%s", n, n == 1 ? "" : "s");
    igTextDisabled("%s", cnt);
    igSameLine(0, 10 * s);
    {
        float aw = 0;
        guix_content_avail(&aw, NULL);
        igDummy(v2(aw - 80 * s, 1));
        igSameLine(0, 0);
    }
    if (gui_ghost_button("Clear", GUI_ICON_TRASH)) {
        pmx_engine_clear_events(app->engine);
    }
    gui_vspace(6 * s);

    float aw = 0, ah = 0;
    guix_content_avail(&aw, &ah);
    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                         ImGuiTableFlags_BordersInnerH |
                         ImGuiTableFlags_SizingStretchProp;
    if (n == 0) {
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_faint[0], t->text_faint[1], t->text_faint[2], 1));
        igTextWrapped("No connections captured yet. Start the engine (demo traffic "
                      "is on by default) to see flows classified here.");
        igPopStyleColor(1);
        return;
    }
    if (igBeginTable("##conns", 5, tf, v2(0, ah), 0)) {
        igTableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 0.20f, 0);
        igTableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 0.34f, 0);
        igTableSetupColumn("Verdict", ImGuiTableColumnFlags_WidthFixed, 90 * s, 0);
        igTableSetupColumn("Via", ImGuiTableColumnFlags_WidthStretch, 0.22f, 0);
        igTableSetupColumn("Rule", ImGuiTableColumnFlags_WidthStretch, 0.22f, 0);
        igTableSetupScrollFreeze(0, 1);
        igTableHeadersRow();
        for (size_t i = 0; i < n; i++) {
            pmx_conn_event *e = &evs[i];
            igTableNextRow(0, 0);
            igTableSetColumnIndex(0);
            igTextUnformatted(e->app_name, NULL);
            igTableSetColumnIndex(1);
            char tgt[300];
            snprintf(tgt, sizeof(tgt), "%s:%u", e->host, (unsigned)e->port);
            igTextUnformatted(tgt, NULL);
            igTableSetColumnIndex(2);
            const float *vc = NULL;
            verdict_color(t, e->verdict, &vc);
            gui_status_pill(pmx_verdict_str(e->verdict), vc);
            igTableSetColumnIndex(3);
            igTextUnformatted(e->via_label, NULL);
            igTableSetColumnIndex(4);
            igTextUnformatted(e->rule_name, NULL);
        }
        if (app->log_autoscroll) {
            igSetScrollHereY(1.0f);
        }
        igEndTable();
    }
}

static void tab_log(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    igTextUnformatted("Auto-scroll", NULL);
    igSameLine(0, 8 * s);
    gui_toggle("##logscroll", &app->log_autoscroll);
    igSameLine(0, 16 * s);
    if (gui_ghost_button("Clear log", GUI_ICON_TRASH)) {
        pmx_mutex_lock(app->log_mutex);
        app->log_len = 0;
        app->log_head = 0;
        pmx_mutex_unlock(app->log_mutex);
    }
    gui_vspace(6 * s);

    float aw = 0, ah = 0;
    guix_content_avail(&aw, &ah);
    if (igBeginChild_Str("##logview", v2(0, ah), ImGuiChildFlags_Borders, 0)) {
        pmx_mutex_lock(app->log_mutex);
        for (size_t i = 0; i < app->log_len; i++) {
            size_t idx = (app->log_head + i) % GUI_LOG_CAP;
            const gui_log_entry *le = &app->log[idx];
            const float *c = t->text_dim;
            if (le->level == PMX_LOG_ERROR) c = t->danger;
            else if (le->level == PMX_LOG_WARN) c = t->warn;
            else if (le->level >= PMX_LOG_INFO) c = t->text;
            igPushStyleColor_Vec4(ImGuiCol_Text, v4(c[0], c[1], c[2], 1));
            igTextWrapped("%s", le->text);
            igPopStyleColor(1);
        }
        pmx_mutex_unlock(app->log_mutex);
        if (app->log_autoscroll) {
            igSetScrollHereY(1.0f);
        }
    }
    igEndChild();
}

void panel_connections(gui_app *app) {
    /* This card must FILL the remaining height, not auto-size: the scrolling
     * table inside sizes itself from the space left over, and an auto-resizing
     * parent would collapse it to nothing (rows clipped away). */
    float availw = 0, availh = 0;
    guix_content_avail(&availw, &availh);
    if (gui_card_begin("##connscard", availh > 0 ? availh : 0)) {
        gui_section_header(GUI_ICON_ROUTE, "Connections & log", NULL);
        gui_vspace(6.0f * guix_dpi_scale());
        if (igBeginTabBar("##conntabs", 0)) {
            if (igBeginTabItem("Live connections", NULL, 0)) {
                tab_connections(app);
                igEndTabItem();
            }
            if (igBeginTabItem("System log", NULL, 0)) {
                tab_log(app);
                igEndTabItem();
            }
            igEndTabBar();
        }
        gui_card_end();
    }
}
