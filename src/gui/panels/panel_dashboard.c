#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static void u64s(char *buf, size_t n, uint64_t v) {
    snprintf(buf, n, "%llu", (unsigned long long)v);
}

static void verdict_colors(const gui_theme *t, pmx_verdict v, const float **col) {
    switch (v) {
    case PMX_VERDICT_PROXY:  *col = t->accent; break;
    case PMX_VERDICT_DIRECT: *col = t->ok; break;
    case PMX_VERDICT_BLOCK:  *col = t->danger; break;
    default:                 *col = t->text_dim; break;
    }
}

static void rel_time(uint64_t ts_ms, char *buf, size_t n) {
    uint64_t now = pmx_now_ms();
    uint64_t d = (now > ts_ms) ? (now - ts_ms) : 0;
    if (d < 1000) {
        snprintf(buf, n, "now");
    } else if (d < 60000) {
        snprintf(buf, n, "%llus ago", (unsigned long long)(d / 1000));
    } else {
        snprintf(buf, n, "%llum ago", (unsigned long long)(d / 60000));
    }
}

void panel_dashboard(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_engine_status es;
    pmx_engine_get_status(app->engine, &es);
    pmx_profile *pf = pmx_engine_profile(app->engine);

    /* Stat tiles. */
    float availw = 0;
    guix_content_avail(&availw, NULL);
    float gap = 12.0f * s;
    float tilew = (availw - gap * 3.0f) / 4.0f;
    char b[32];

    u64s(b, sizeof(b), es.flows_total);
    gui_stat_tile(GUI_ICON_ROUTE, "Total flows", b, t->accent, tilew);
    igSameLine(0, gap);
    u64s(b, sizeof(b), es.flows_proxied);
    gui_stat_tile(GUI_ICON_LINK, "Proxied", b, t->accent, tilew);
    igSameLine(0, gap);
    u64s(b, sizeof(b), es.flows_direct);
    gui_stat_tile(GUI_ICON_GLOBE, "Direct", b, t->ok, tilew);
    igSameLine(0, gap);
    u64s(b, sizeof(b), es.flows_blocked);
    gui_stat_tile(GUI_ICON_SHIELD, "Blocked", b, t->danger, tilew);

    gui_vspace(14.0f * s);

    /* Two different truths, and conflating them misleads in opposite directions.
     * backend_real tracks whether PROXY redirection has been proven on the wire;
     * it is false even on the WinDivert backend, which sees and blocks real
     * connections for real. Telling that user they are watching "demo traffic"
     * understates what is happening on their machine. */
    if (!es.backend_real) {
        if (es.backend_can_block) {
            gui_note(GUI_ICON_ROUTE,
                     "Real connections, unproven proxying. These are actual "
                     "per-app connections and Block rules genuinely drop them. "
                     "What is NOT proven is redirection to a proxy: the rewrite "
                     "has never been observed on the wire, so a Proxy verdict "
                     "fails closed rather than leaking out unproxied.",
                     t->warn);
        } else {
            gui_note(GUI_ICON_ROUTE,
                     "Simulated backend. ProxiMight is running on the stub "
                     "backend: it exercises the full rule/chain/lockdown pipeline "
                     "against demo traffic but does not touch real OS "
                     "connections. Wire up the WinDivert backend to proxify "
                     "actual apps.",
                     t->warn);
        }
        gui_vspace(12.0f * s);
    }

    /* Overview + recent activity, side by side. */
    if (igBeginTable("##dashcols", 2, ImGuiTableFlags_None, v2(0, 0), 0)) {
        igTableSetupColumn("a", ImGuiTableColumnFlags_WidthStretch, 0.42f, 0);
        igTableSetupColumn("b", ImGuiTableColumnFlags_WidthStretch, 0.58f, 0);
        igTableNextRow(0, 0);

        igTableSetColumnIndex(0);
        if (gui_card_begin("##overview", 0)) {
            gui_section_header(GUI_ICON_GLOBE, "Overview", NULL);
            gui_vspace(6.0f * s);
            gui_status_pill(es.running ? "Engine running" : "Engine idle",
                            es.running ? t->ok : t->text_faint);
            gui_vspace(6.0f * s);

            igTextUnformatted("Backend", NULL);
            igSameLine(0, 8 * s);
            char bk[64];
            snprintf(bk, sizeof(bk), "%s (%s)", es.backend_name,
                     es.backend_real ? "real" : "simulated");
            gui_badge(bk, gui_theme_u32(t->surface2), gui_theme_u32(t->text_dim));

            gui_vspace(4.0f * s);
            char ld[80];
            snprintf(ld, sizeof(ld), "Lockdown: %s",
                     pmx_lockdown_state_str(es.lockdown_state));
            const float *lc = t->text_faint;
            if (es.lockdown_state == PMX_LD_ARMED_HEALTHY) lc = t->ok;
            else if (es.lockdown_state == PMX_LD_TRIPPED_BLOCKING) lc = t->danger;
            else if (es.lockdown_state == PMX_LD_FAILING_OVER) lc = t->warn;
            gui_status_pill(ld, lc);

            gui_vspace(8.0f * s);
            if (pf != NULL) {
                char line[128];
                snprintf(line, sizeof(line),
                         "Profile \"%s\": %zu proxies, %zu rules, %zu chains",
                         pf->label, pf->proxy_count, pf->rule_count,
                         pf->chain_count);
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_dim[0],
                                                        t->text_dim[1],
                                                        t->text_dim[2], 1));
                igTextWrapped("%s", line);
                igPopStyleColor(1);
            }
            gui_vspace(6.0f * s);
            if (!es.running) {
                if (gui_primary_button("Start proxifying", GUI_ICON_PLAY)) {
                    pmx_engine_start(app->engine);
                }
            } else {
                if (gui_danger_button("Stop", GUI_ICON_STOP)) {
                    pmx_engine_stop(app->engine);
                }
            }
            gui_card_end();
        }

        igTableSetColumnIndex(1);
        if (gui_card_begin("##recent", 0)) {
            gui_section_header(GUI_ICON_ROUTE, "Recent activity", NULL);
            gui_vspace(4.0f * s);
            pmx_conn_event evs[10];
            size_t n = pmx_engine_recent_events(app->engine, evs, 10);
            if (n == 0) {
                igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_faint[0],
                                                        t->text_faint[1],
                                                        t->text_faint[2], 1));
                igTextWrapped("No connections yet. Press Start to begin.");
                igPopStyleColor(1);
            } else if (igBeginTable("##recenttbl", 3,
                                    ImGuiTableFlags_RowBg |
                                        ImGuiTableFlags_SizingStretchProp,
                                    v2(0, 0), 0)) {
                igTableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 0.30f, 0);
                igTableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 0.50f, 0);
                igTableSetupColumn("Verdict", ImGuiTableColumnFlags_WidthStretch, 0.20f, 0);
                for (size_t i = n; i-- > 0;) {
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
                    verdict_colors(t, e->verdict, &vc);
                    gui_status_pill(pmx_verdict_str(e->verdict), vc);
                }
                igEndTable();
            }
            gui_card_end();
        }
        igEndTable();
    }
}
