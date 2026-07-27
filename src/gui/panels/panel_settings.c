#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <string.h>

void panel_settings(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    pmx_profile *pf = pmx_engine_profile(app->engine);
    pmx_engine_status es;
    pmx_engine_get_status(app->engine, &es);

    /* Profile. */
    if (gui_card_begin("##setprofile", 0)) {
        gui_section_header(GUI_ICON_LIST, "Profile", NULL);
        gui_vspace(6 * s);
        gui_field_label("Working profile file");
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
        igTextWrapped("%s", app->profile_path);
        igPopStyleColor(1);
        gui_vspace(6 * s);
        gui_field_label("Profile label");
        gui_input_text("##proflabel", "Profile name", pf->label, sizeof(pf->label),
                       false);
        gui_vspace(8 * s);
        if (gui_primary_button("Save now", GUI_ICON_CHECK)) {
            gui_app_save(app);
        }
        igSameLine(0, 8 * s);
        if (gui_secondary_button("Reload from disk", GUI_ICON_REFRESH)) {
            if (pmx_engine_load_profile(app->engine, app->profile_path) == PMX_OK) {
                gui_app_status(app, "Profile reloaded.");
            } else {
                gui_app_status(app, "Reload failed (no saved profile?).");
            }
        }
        gui_card_end();
    }
    gui_vspace(12 * s);

    /* General. */
    if (gui_card_begin("##setgeneral", 0)) {
        gui_section_header(GUI_ICON_GEAR, "General", NULL);
        gui_vspace(6 * s);
        igTextUnformatted("Generate demo traffic (stub backend)", NULL);
        igSameLine(0, 10 * s);
        gui_toggle("##demotraffic", &pf->settings.demo_traffic);
        gui_vspace(4 * s);
        gui_field_label("Demo traffic interval (ms)");
        gui_input_int("##demoint", &pf->settings.demo_interval_ms, 200, 10000);
        gui_vspace(8 * s);
        igTextUnformatted("Resolve DNS through the proxy", NULL);
        igSameLine(0, 10 * s);
        gui_toggle("##dnsthrough", &pf->settings.dns_through_proxy);
        if (es.running) {
            gui_vspace(6 * s);
            igTextDisabled("Demo-traffic changes apply the next time you Start.");
        }
        gui_card_end();
    }
    gui_vspace(12 * s);

    /* Checker defaults. */
    if (gui_card_begin("##setcheck", 0)) {
        gui_section_header(GUI_ICON_REFRESH, "Proxy checker defaults", NULL);
        gui_vspace(6 * s);
        bool changed = false;
        if (igBeginTable("##ckt", 2, 0, v2(0, 0), 0)) {
            /* Stretch columns, host wider than port — see the note on ##ldnums in
             * panel_lockdown.c for why an undeclared column collapses the input. */
            igTableSetupColumn("h", ImGuiTableColumnFlags_WidthStretch, 0.7f, 0);
            igTableSetupColumn("p", ImGuiTableColumnFlags_WidthStretch, 0.3f, 0);
            igTableNextRow(0, 0);
            igTableSetColumnIndex(0);
            gui_field_label("Probe host");
            if (gui_input_text("##ckhost", "example.com",
                               pf->settings.check.probe_host,
                               sizeof(pf->settings.check.probe_host), false))
                changed = true;
            igTableSetColumnIndex(1);
            gui_field_label("Probe port");
            int pp = (int)pf->settings.check.probe_port;
            if (gui_input_int("##ckport", &pp, 1, 65535)) {
                pf->settings.check.probe_port = (pmx_port)pp;
                changed = true;
            }
            igEndTable();
        }
        gui_vspace(4 * s);
        gui_field_label("Timeout (ms)");
        if (gui_input_int("##cktmo", &pf->settings.check.timeout_ms, 500, 30000))
            changed = true;
        gui_vspace(4 * s);
        gui_field_label("Egress IP-echo service (used only when egress check is on)");
        if (gui_input_text("##ckegs", "api.ipify.org",
                           pf->settings.check.egress_service,
                           sizeof(pf->settings.check.egress_service), false))
            changed = true;
        if (changed) {
            pmx_checker_set_opts(pmx_engine_checker(app->engine),
                                 &pf->settings.check);
        }
        gui_card_end();
    }
    gui_vspace(12 * s);

    /* Appearance. */
    if (gui_card_begin("##setappearance", 0)) {
        gui_section_header(GUI_ICON_GLOBE, "Appearance", NULL);
        gui_vspace(6 * s);
        igTextUnformatted("Dark mode", NULL);
        igSameLine(0, 10 * s);
        if (gui_toggle("##darkmode", &app->dark)) {
            if (app->dark) {
                gui_theme_dark(&app->theme);
            } else {
                gui_theme_light(&app->theme);
            }
            gui_app_apply_theme(app);
        }
        gui_card_end();
    }
    gui_vspace(12 * s);

    /* Redirection backend. */
    if (gui_card_begin("##setbackend", 0)) {
        gui_section_header(GUI_ICON_ROUTE, "Redirection backend", NULL);
        gui_vspace(6 * s);
        pmx_backend *be = pmx_engine_backend(app->engine);
        char line[200];
        snprintf(line, sizeof(line),
                 "Active: %s   •   per-app attribution: %s   •   can block: %s   "
                 "•   redirects traffic: %s",
                 be ? be->name : "none",
                 (be && be->caps.per_app) ? "yes" : "no",
                 (be && be->caps.can_block) ? "yes" : "no",
                 (be && be->caps.real) ? "yes" : "no");
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
        igTextWrapped("%s", line);
        igPopStyleColor(1);
        gui_vspace(8 * s);

        if (es.running) {
            igTextDisabled("Stop the engine to switch backends.");
        } else {
            if (gui_secondary_button("Use stub (demo traffic)", GUI_ICON_ROUTE)) {
                pmx_backend *nb = pmx_backend_stub_create();
                if (nb != NULL && pmx_engine_set_backend(app->engine, nb) == PMX_OK) {
                    gui_app_status(app, "Switched to the stub backend.");
                }
            }
            igSameLine(0, 8 * s);
            if (gui_primary_button("Use platform backend", GUI_ICON_SHIELD)) {
                pmx_backend *nb = pmx_backend_platform_create();
                if (nb != NULL && pmx_engine_set_backend(app->engine, nb) == PMX_OK) {
                    char m[96];
                    snprintf(m, sizeof(m), "Switched to '%s'.", nb->name);
                    gui_app_status(app, m);
                } else {
                    gui_app_status(app, "Platform backend unavailable.");
                }
            }
        }
        gui_vspace(8 * s);
        gui_note(GUI_ICON_SHIELD,
                 "The platform backend needs the WinDivert SDK at build time and "
                 "Administrator at run time. It observes real per-app connections, "
                 "classifies them against your rules, and genuinely BLOCKS the "
                 "ones a Block rule matches. Proxy redirection is written but has "
                 "never been observed on the wire, so a Proxy verdict fails closed "
                 "instead of leaking out unproxied. See docs/SETUP-WINDIVERT.md.",
                 t->warn);
        gui_card_end();
    }
    gui_vspace(12 * s);

    /* Backend + about. */
    if (gui_card_begin("##setabout", 0)) {
        gui_section_header(GUI_ICON_CHAIN, "About ProxiMight", NULL);
        gui_vspace(6 * s);
        char ver[96];
        snprintf(ver, sizeof(ver), "Version %s  •  backend: %s (%s)",
                 PMX_VERSION_STRING, es.backend_name,
                 es.backend_real ? "real redirection" : "simulated");
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
        igTextWrapped("%s", ver);
        igPopStyleColor(1);
        gui_vspace(8 * s);
        gui_note(GUI_ICON_SHIELD,
                 "Unaudited pre-alpha. A proxy is not a VPN and adds no "
                 "encryption; your privacy is only as good as the proxies you "
                 "configure. Don't rely on this to protect anything that matters "
                 "yet.",
                 t->warn);
        gui_vspace(8 * s);
        igTextUnformatted("Developer", NULL);
        igSameLine(0, 10 * s);
        gui_toggle("##imguidemo", &app->show_demo);
        igSameLine(0, 8 * s);
        igTextDisabled("show Dear ImGui demo window");
        gui_card_end();
    }
}
