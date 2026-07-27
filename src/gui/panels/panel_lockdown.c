#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

static const char *const kModes[] = {"Off", "Fail closed", "Fail to backup",
                                      "Fail open (leaky)"};

static const char *mode_help(pmx_lockdown_mode m) {
    switch (m) {
    case PMX_LOCKDOWN_OFF:
        return "No enforcement. If the proxy drops, apps fall back to a direct "
               "connection (this leaks).";
    case PMX_LOCKDOWN_FAIL_CLOSED:
        return "Kill switch. While armed, only the proxy endpoint(s) and loopback "
               "may leave the machine; if the proxy is unreachable, everything "
               "else is blocked so nothing leaks direct.";
    case PMX_LOCKDOWN_FAIL_BACKUP:
        /* Says what it DOES, not what the name suggests. Promoting a backup is
         * not implemented (see pmx_lockdown.h), and a mode that claims a
         * continuity it cannot deliver is exactly the kind of false protection
         * this project treats as a defect. */
        return "Intended to promote a backup proxy when the primary dies — NOT "
               "IMPLEMENTED yet, so this currently behaves exactly like fail "
               "closed: egress is blocked. Safe, but it will not keep you "
               "connected. Pick fail closed unless you want the state label.";
    case PMX_LOCKDOWN_FAIL_OPEN:
        return "Explicitly leaky: if the proxy drops, traffic is allowed to go "
               "out directly. Convenient, not private. Use with intent.";
    default:
        return "";
    }
}

void panel_lockdown(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);
    pmx_lockdown *ld = pmx_engine_lockdown(app->engine);
    pmx_engine_status es;
    pmx_engine_get_status(app->engine, &es);

    /* State hero. */
    if (gui_card_begin("##ldstate", 0)) {
        const float *c = t->text_faint;
        gui_icon_id ic = GUI_ICON_SHIELD;
        switch (es.lockdown_state) {
        case PMX_LD_ARMED_HEALTHY: c = t->ok; break;
        case PMX_LD_TRIPPED_BLOCKING: c = t->danger; ic = GUI_ICON_LOCK; break;
        case PMX_LD_FAILING_OVER: c = t->warn; break;
        case PMX_LD_FAILED_OPEN: c = t->warn; break;
        default: c = t->text_faint; break;
        }
        float cx = 0, cy = 0;
        guix_cursor_screen(&cx, &cy);
        gui_icon(ic, cx, cy + 2 * s, 34 * s, gui_theme_u32(c));
        igDummy(v2(42 * s, 34 * s));
        igSameLine(0, 6 * s);
        igBeginGroup();
        guix_push_heading_font();
        igTextUnformatted(pmx_lockdown_state_str(es.lockdown_state), NULL);
        guix_pop_font();
        char sub[96];
        snprintf(sub, sizeof(sub), "%s  •  firewall: %s",
                 es.running ? "armed" : "disarmed (engine idle)",
                 "stub (logs only)");
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
        igTextUnformatted(sub, NULL);
        igPopStyleColor(1);
        igEndGroup();
        gui_card_end();
    }
    gui_vspace(12 * s);

    gui_note(GUI_ICON_SHIELD,
             "Enforcement backend is the stub firewall: it logs exactly what it "
             "would block but does not touch the real firewall yet. Real "
             "fail-closed blocking needs WFP + Administrator (Windows) or pf + "
             "root (macOS).",
             t->warn);
    gui_vspace(12 * s);

    if (gui_card_begin("##ldpolicy", 0)) {
        gui_section_header(GUI_ICON_LOCK, "Lockdown policy", NULL);
        gui_vspace(8 * s);

        bool changed = false;
        gui_field_label("Mode");
        int mode = (int)pf->lockdown.mode;
        if (gui_combo("##ldmode", &mode, kModes, 4)) {
            pf->lockdown.mode = (pmx_lockdown_mode)mode;
            changed = true;
        }
        gui_vspace(4 * s);
        gui_note(GUI_ICON_SHIELD, mode_help(pf->lockdown.mode),
                 pf->lockdown.mode == PMX_LOCKDOWN_FAIL_OPEN ? t->warn : t->accent);
        gui_vspace(10 * s);

        igTextUnformatted("Block all egress until the proxy is verified", NULL);
        igSameLine(0, 10 * s);
        if (gui_toggle("##lduntil", &pf->lockdown.block_until_verified)) changed = true;
        gui_vspace(4 * s);
        igTextUnformatted("Block DNS leaks (force resolution through the tunnel)", NULL);
        igSameLine(0, 10 * s);
        if (gui_toggle("##lddns", &pf->lockdown.block_dns_leak)) changed = true;
        gui_vspace(4 * s);
        igTextUnformatted("Block IPv6 egress", NULL);
        igSameLine(0, 10 * s);
        if (gui_toggle("##ldipv6", &pf->lockdown.block_ipv6)) changed = true;
        gui_vspace(10 * s);

        if (igBeginTable("##ldnums", 3, 0, v2(0, 0), 0)) {
            /* Declare the columns as STRETCH. Cards are auto-resizing children,
             * which makes a table's default sizing FixedFit — and our inputs ask
             * for width -1 ("fill the column"), which in a fit-to-content column
             * has nothing to resolve against. The result was unreadable: this row
             * rendered "Failures to trip" with a zero-width box and clipped the
             * health interval mid-digit. Same fix as ##hostport in panel_proxies. */
            igTableSetupColumn("i", ImGuiTableColumnFlags_WidthStretch, 1.0f, 0);
            igTableSetupColumn("f", ImGuiTableColumnFlags_WidthStretch, 1.0f, 0);
            igTableSetupColumn("s", ImGuiTableColumnFlags_WidthStretch, 1.0f, 0);
            igTableNextRow(0, 0);
            igTableSetColumnIndex(0);
            gui_field_label("Health interval (ms)");
            if (gui_input_int("##ldint", &pf->lockdown.health_interval_ms, 500,
                              60000))
                changed = true;
            igTableSetColumnIndex(1);
            gui_field_label("Failures to trip");
            if (gui_input_int("##ldfail", &pf->lockdown.failures_before_trip, 1, 20))
                changed = true;
            igTableSetColumnIndex(2);
            gui_field_label("Successes to restore");
            if (gui_input_int("##ldok", &pf->lockdown.successes_before_restore, 1,
                              20))
                changed = true;
            igEndTable();
        }

        if (changed) {
            pmx_lockdown_set_policy(ld, &pf->lockdown);
        }

        gui_vspace(10 * s);
        char stats[128];
        snprintf(stats, sizeof(stats),
                 "watcher: %d consecutive failure(s), %d success(es)",
                 pmx_lockdown_consecutive_failures(ld),
                 pmx_lockdown_consecutive_successes(ld));
        igTextDisabled("%s", stats);
        gui_card_end();
    }
}
