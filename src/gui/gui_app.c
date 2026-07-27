#include "gui_app.h"
#include "gui_widgets.h"
#include "gui_backend.h"
#include "gui_icons.h"
#include "gui_imgui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *kNavLabels[GUI_NAV__COUNT] = {
    "Dashboard", "Proxy servers", "Rules",         "Chains",
    "VPN tunnels", "Connections", "Proxy checker", "Lockdown",
    "Settings",
};
static const gui_icon_id kNavIcons[GUI_NAV__COUNT] = {
    GUI_ICON_GLOBE, GUI_ICON_LINK,  GUI_ICON_LIST,    GUI_ICON_CHAIN,
    GUI_ICON_LOCK,  GUI_ICON_ROUTE, GUI_ICON_REFRESH, GUI_ICON_SHIELD,
    GUI_ICON_GEAR,
};

/* ---- log sink (thread-safe) ------------------------------------------- */

static void log_sink(void *user, pmx_log_level level, uint64_t ts_ms,
                     const char *line) {
    (void)ts_ms;
    gui_app *app = (gui_app *)user;
    if (app == NULL || app->log_mutex == NULL) {
        return;
    }
    pmx_mutex_lock(app->log_mutex);
    size_t idx;
    if (app->log_len < GUI_LOG_CAP) {
        idx = (app->log_head + app->log_len) % GUI_LOG_CAP;
        app->log_len++;
    } else {
        idx = app->log_head;
        app->log_head = (app->log_head + 1) % GUI_LOG_CAP;
    }
    app->log[idx].level = (int)level;
    pmx_strlcpy(app->log[idx].text, line, sizeof(app->log[idx].text));
    pmx_mutex_unlock(app->log_mutex);
}

/* ---- lifecycle --------------------------------------------------------- */

static void default_profile_path(char *buf, size_t n) {
    const char *base = NULL;
#if defined(_WIN32)
    base = getenv("APPDATA");
    if (base != NULL) {
        snprintf(buf, n, "%s\\ProxiMight\\profile.pmxprofile", base);
        return;
    }
#else
    base = getenv("HOME");
    if (base != NULL) {
        snprintf(buf, n, "%s/.config/proximight/profile.pmxprofile", base);
        return;
    }
#endif
    pmx_strlcpy(buf, "profile.pmxprofile", n);
}

gui_app *gui_app_create(pmx_engine *engine) {
    gui_app *app = (gui_app *)calloc(1, sizeof(*app));
    if (app == NULL) {
        return NULL;
    }
    app->engine = engine;
    app->dark = true;
    gui_theme_dark(&app->theme);
    app->nav = GUI_NAV_DASHBOARD;
    app->log_autoscroll = true;
    app->log_mutex = pmx_mutex_create();

    default_profile_path(app->profile_path, sizeof(app->profile_path));

    pmx_log_set_sink(log_sink, app);

    /* Load a saved profile if present; otherwise keep the seeded defaults. */
    pmx_status load_st = pmx_engine_load_profile(engine, app->profile_path);
    if (load_st == PMX_OK) {
        PMX_LOGI("Loaded working profile from %s", app->profile_path);
    } else if (load_st == PMX_ERR_IO) {
        PMX_LOGI("No saved profile; using seeded defaults.");
    } else {
        /* The file exists but couldn't be read (sealed for another user/machine,
         * or corrupt). The engine has locked saving so we won't clobber it. */
        PMX_LOGE("Existing profile at %s could not be read (%s). Running with "
                 "defaults; it will not be overwritten. Remove or fix the file "
                 "to start fresh.",
                 app->profile_path, pmx_status_str(load_st));
        gui_app_status(app, "Existing profile couldn't be read — running read-only.");
    }

    pmx_profile *pf = pmx_engine_profile(engine);
    if (pf != NULL && pf->proxy_count > 0) {
        app->sel_proxy = pf->proxies[0].id;
    }
    if (pf != NULL && pf->chain_count > 0) {
        app->sel_chain = pf->chains[0].id;
    }
    return app;
}

void gui_app_destroy(gui_app *app) {
    if (app == NULL) {
        return;
    }
    pmx_log_set_sink(NULL, NULL);
    if (app->mtr_job != NULL) {
        pmx_mtr_free(app->mtr_job);
    }
    pmx_mutex_destroy(app->log_mutex);
    free(app);
}

void gui_app_apply_theme(gui_app *app) {
    if (app == NULL) {
        return;
    }
    gui_theme_apply(&app->theme);
    gui_widgets_use_theme(&app->theme);

    /* The OS draws its own title bar, so it has to be told about the theme too —
     * otherwise a light caption sits directly on top of the dark UI. Tint it to
     * the app background rather than plain black so the caption and the window
     * body read as one surface. Both callers of this function (start-up and the
     * Settings toggle) therefore switch the caption as well. */
    const gui_theme *t = &app->theme;
    guix_set_titlebar_theme(t->dark, gui_theme_u32(t->bg), gui_theme_u32(t->text),
                            gui_theme_u32(t->border));
}

void gui_app_bg(gui_app *app, float *r, float *g, float *b) {
    if (app == NULL) {
        return;
    }
    if (r) *r = app->theme.bg[0];
    if (g) *g = app->theme.bg[1];
    if (b) *b = app->theme.bg[2];
}

void gui_app_status(gui_app *app, const char *msg) {
    if (app == NULL) {
        return;
    }
    pmx_strlcpy(app->status_msg, msg ? msg : "", sizeof(app->status_msg));
    app->status_msg_until = pmx_now_ms() + 4000;
}

void gui_app_save(gui_app *app) {
    if (app == NULL) {
        return;
    }
    pmx_status st = pmx_engine_save_profile(app->engine, app->profile_path);
    gui_app_status(app, st == PMX_OK ? "Profile saved." : "Save failed.");
}

/* ---- check cache ------------------------------------------------------- */

void gui_app_store_check(gui_app *app, const pmx_check_result *r) {
    for (size_t i = 0; i < app->check_count; i++) {
        if (app->checks[i].proxy_id == r->proxy_id &&
            app->checks[i].hop_index == r->hop_index) {
            app->checks[i] = *r;
            return;
        }
    }
    if (app->check_count < PMX_ARRAY_LEN(app->checks)) {
        app->checks[app->check_count++] = *r;
    }
}

const pmx_check_result *gui_app_find_check(gui_app *app, pmx_id proxy_id,
                                           int hop_index) {
    for (size_t i = 0; i < app->check_count; i++) {
        if (app->checks[i].proxy_id == proxy_id &&
            app->checks[i].hop_index == hop_index) {
            return &app->checks[i];
        }
    }
    return NULL;
}

void gui_app_start_path_scan(gui_app *app, const char *host) {
    if (app == NULL || host == NULL || host[0] == '\0') {
        return;
    }
    if (app->mtr_job != NULL) {
        pmx_mtr_free(app->mtr_job);
        app->mtr_job = NULL;
    }
    pmx_strlcpy(app->mtr_target, host, sizeof(app->mtr_target));
    app->mtr_have_result = false;
    memset(&app->mtr_result, 0, sizeof(app->mtr_result));

    pmx_path_opts o;
    pmx_path_opts_defaults(&o);
    o.cycles = 2;      /* keep the UI responsive */
    o.timeout_ms = 800;
    app->mtr_job = pmx_mtr_start(host, &o);
    if (app->mtr_job == NULL) {
        gui_app_status(app, "Could not start the path scan.");
        return;
    }
    app->nav = GUI_NAV_CHECKER;
    gui_app_status(app, "Tracing network path…");
}

void gui_app_request_delete(gui_app *app, int kind, pmx_id id,
                            const char *label) {
    app->confirm_open = true;
    app->confirm_kind = kind;
    app->confirm_id = id;
    pmx_strlcpy(app->confirm_label, label ? label : "", sizeof(app->confirm_label));
}

/* ---- sidebar ----------------------------------------------------------- */

static bool nav_item(gui_app *app, gui_icon_id icon, const char *label, int nav) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();
    float availw = 0, availh = 0;
    guix_content_avail(&availw, &availh);
    float h = 40.0f * s;

    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    char id[64];
    snprintf(id, sizeof(id), "##nav%d", nav);
    bool pressed = igInvisibleButton(id, v2(availw, h), 0);
    bool hovered = igIsItemHovered(0);
    bool selected = (app->nav == nav);

    unsigned bg = selected ? gui_theme_u32a(t->accent, t->dark ? 0.20f : 0.14f)
                           : (hovered ? gui_theme_u32(t->surface2) : 0);
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + availw, y0 + h, bg, 8.0f * s);
    }
    if (selected) {
        guix_draw_rect_filled(x0, y0 + 8.0f * s, x0 + 3.5f * s, y0 + h - 8.0f * s,
                              gui_theme_u32(t->accent), 2.0f * s);
    }
    unsigned fg = selected ? gui_theme_u32(t->accent)
                           : (hovered ? gui_theme_u32(t->text)
                                      : gui_theme_u32(t->text_dim));
    float iconsz = 18.0f * s;
    gui_icon(icon, x0 + 14.0f * s, y0 + (h - iconsz) * 0.5f, iconsz, fg);
    float tw = 0, th = 0;
    guix_calc_text(label, &tw, &th);
    guix_draw_text(x0 + 14.0f * s + iconsz + 12.0f * s, y0 + (h - th) * 0.5f, fg,
                   label);
    if (pressed) {
        app->nav = nav;
    }
    return pressed;
}

static void build_sidebar(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    /* Brand block. */
    float bx = 0, by = 0;
    guix_cursor_screen(&bx, &by);
    guix_draw_chain_mark(bx + 20.0f * s, by + 24.0f * s, 0.62f * s,
                         gui_theme_u32(t->accent), gui_theme_u32(t->accent_dim),
                         3.0f);
    guix_push_heading_font();
    guix_draw_text(bx + 44.0f * s, by + 8.0f * s, gui_theme_u32(t->text),
                   "ProxiMight");
    guix_pop_font();
    guix_draw_text(bx + 44.0f * s, by + 32.0f * s, gui_theme_u32(t->text_faint),
                   "per-app proxifier");
    igDummy(v2(0, 58.0f * s));
    gui_vspace(6.0f * s);

    for (int i = 0; i < GUI_NAV__COUNT; i++) {
        nav_item(app, kNavIcons[i], kNavLabels[i], i);
        gui_vspace(2.0f * s);
    }

    /* Push the control block to the bottom. */
    float availw = 0, availh = 0;
    guix_content_avail(&availw, &availh);
    float bottom_h = 132.0f * s;
    if (availh > bottom_h) {
        igDummy(v2(0, availh - bottom_h));
    }

    guix_cursor_screen(&bx, &by);
    guix_draw_line(bx, by, bx + availw, by, gui_theme_u32(t->border), 1.0f);
    gui_vspace(10.0f * s);

    bool running = pmx_engine_is_running(app->engine);
    if (running) {
        if (gui_button("##stopbtn", GUI_ICON_STOP, true, "Stop", GUI_BTN_DANGER,
                       availw)) {
            pmx_engine_stop(app->engine);
            gui_app_status(app, "Stopped.");
        }
    } else {
        if (gui_button("##startbtn", GUI_ICON_PLAY, true, "Start proxifying",
                       GUI_BTN_PRIMARY, availw)) {
            pmx_status st = pmx_engine_start(app->engine);
            gui_app_status(app, st == PMX_OK ? "Proxifying started."
                                             : "Failed to start.");
        }
    }
    gui_vspace(8.0f * s);

    pmx_engine_status es;
    pmx_engine_get_status(app->engine, &es);
    gui_status_pill(running ? "Engine running" : "Engine idle",
                    running ? t->ok : t->text_faint);
    gui_vspace(4.0f * s);
    {
        const float *lc = t->text_faint;
        switch (es.lockdown_state) {
        case PMX_LD_ARMED_HEALTHY: lc = t->ok; break;
        case PMX_LD_TRIPPED_BLOCKING: lc = t->danger; break;
        case PMX_LD_FAILING_OVER: lc = t->warn; break;
        case PMX_LD_FAILED_OPEN: lc = t->warn; break;
        default: lc = t->text_faint; break;
        }
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "Lockdown: %s",
                 pmx_lockdown_state_str(es.lockdown_state));
        gui_status_pill(lbl, lc);
    }
}

/* ---- top bar ----------------------------------------------------------- */

static void build_topbar(gui_app *app) {
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    /* The row's full width, measured before anything is on this line. Used for
     * the separator underneath — NOT for right-aligning the button (see below). */
    float availw = 0, availh = 0;
    guix_content_avail(&availw, &availh);

    guix_push_heading_font();
    igTextUnformatted(kNavLabels[app->nav], NULL);
    guix_pop_font();

    /* Right-aligned actions.
     *
     * guix_content_avail() is measured from the CURRENT cursor, so it has to be
     * re-read after igSameLine() has put the cursor back beside the heading.
     * This used to pad by the pre-heading width, which overshot the right edge by
     * exactly the heading's own width and pushed "Save profile" off screen — the
     * wider the panel name, the more of the button disappeared. The width also
     * has to come from gui_button_width() rather than a guessed constant,
     * because the button sizes itself to its label and font. */
    const float gap = 8.0f * s;
    igSameLine(0, gap);
    float restw = 0, resth = 0;
    guix_content_avail(&restw, &resth);
    const float btnw = gui_button_width("Save profile", true, 0.0f);
    const float pad = restw - btnw;
    if (pad > 0.0f) {
        igDummy(v2(pad, 1));
        igSameLine(0, 0);
    }
    if (gui_secondary_button("Save profile", GUI_ICON_CHECK)) {
        gui_app_save(app);
    }

    if (app->status_msg[0] != '\0' && pmx_now_ms() < app->status_msg_until) {
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
        igTextUnformatted(app->status_msg, NULL);
        igPopStyleColor(1);
    } else {
        gui_vspace(igGetTextLineHeight());
    }

    float lx = 0, ly = 0;
    guix_cursor_screen(&lx, &ly);
    guix_draw_line(lx, ly, lx + availw, ly, gui_theme_u32(t->border), 1.0f);
    gui_vspace(10.0f * s);
}

/* ---- delete confirmation ---------------------------------------------- */

static void render_confirm(gui_app *app) {
    if (app->confirm_open) {
        igOpenPopup_Str("##confirmdel", 0);
        app->confirm_open = false;
    }
    ImGuiViewport *vp = igGetMainViewport();
    igSetNextWindowPos(v2(vp->Pos.x + vp->Size.x * 0.5f,
                          vp->Pos.y + vp->Size.y * 0.5f),
                       ImGuiCond_Always, v2(0.5f, 0.5f));
    if (igBeginPopupModal("##confirmdel", NULL,
                          ImGuiWindowFlags_AlwaysAutoResize |
                              ImGuiWindowFlags_NoTitleBar)) {
        gui_section_header(GUI_ICON_TRASH, "Delete?", NULL);
        gui_vspace(4.0f);
        char msg[256];
        const char *kind = app->confirm_kind == 0   ? "proxy"
                           : app->confirm_kind == 1 ? "rule"
                           : app->confirm_kind == 3 ? "VPN tunnel"
                                                    : "chain";
        snprintf(msg, sizeof(msg), "Remove the %s \"%s\"? This cannot be undone.",
                 kind, app->confirm_label);
        igTextWrapped("%s", msg);
        gui_vspace(10.0f);

        if (gui_secondary_button("Cancel", GUI_ICON_CROSS)) {
            igCloseCurrentPopup();
        }
        igSameLine(0, 8.0f);
        if (gui_danger_button("Delete", GUI_ICON_TRASH)) {
            pmx_profile *pf = pmx_engine_profile(app->engine);
            if (app->confirm_kind == 0) {
                pmx_profile_remove_proxy(pf, app->confirm_id);
            } else if (app->confirm_kind == 1) {
                pmx_profile_remove_rule(pf, app->confirm_id);
            } else if (app->confirm_kind == 3) {
                pmx_profile_remove_vpn(pf, app->confirm_id);
            } else {
                pmx_profile_remove_chain(pf, app->confirm_id);
            }
            gui_app_status(app, "Deleted.");
            igCloseCurrentPopup();
        }
        igEndPopup();
    }
}

/* ---- frame ------------------------------------------------------------- */

void gui_app_frame(gui_app *app) {
    if (app == NULL) {
        return;
    }
    const gui_theme *t = &app->theme;
    const float s = guix_dpi_scale();

    /* Drain interactive checker results into the cache every frame. */
    pmx_checker *chk = pmx_engine_checker(app->engine);
    pmx_check_result cr;
    while (pmx_checker_poll(chk, &cr)) {
        gui_app_store_check(app, &cr);
    }

    /* Collect a finished path scan. */
    if (app->mtr_job != NULL && !app->mtr_have_result) {
        if (pmx_mtr_done(app->mtr_job, &app->mtr_result)) {
            app->mtr_have_result = true;
        }
    }

    ImGuiViewport *vp = igGetMainViewport();
    igSetNextWindowPos(vp->Pos, ImGuiCond_Always, v2(0, 0));
    igSetNextWindowSize(vp->Size, ImGuiCond_Always);

    igPushStyleVar_Float(ImGuiStyleVar_WindowRounding, 0.0f);
    igPushStyleVar_Float(ImGuiStyleVar_WindowBorderSize, 0.0f);
    igPushStyleVar_Vec2(ImGuiStyleVar_WindowPadding, v2(0, 0));
    ImGuiWindowFlags rootflags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    igBegin("##root", NULL, rootflags);
    igPopStyleVar(3);

    /* Sidebar. */
    float sw = 236.0f * s;
    igPushStyleColor_Vec4(ImGuiCol_ChildBg,
                          v4(t->surface[0], t->surface[1], t->surface[2], 1));
    igBeginChild_Str("##sidebar", v2(sw, 0), ImGuiChildFlags_AlwaysUseWindowPadding,
                     0);
    build_sidebar(app);
    igEndChild();
    igPopStyleColor(1);

    /* Right-edge divider of the sidebar. */
    {
        float wx = 0, wy = 0, ww = 0, wh = 0;
        guix_window_pos(&wx, &wy);
        guix_window_size(&ww, &wh);
        guix_draw_line(wx + sw, wy, wx + sw, wy + wh, gui_theme_u32(t->border),
                       1.0f);
    }

    igSameLine(0, 0);

    igBeginChild_Str("##content", v2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding,
                     0);
    build_topbar(app);
    switch (app->nav) {
    case GUI_NAV_DASHBOARD:   panel_dashboard(app); break;
    case GUI_NAV_PROXIES:     panel_proxies(app); break;
    case GUI_NAV_RULES:       panel_rules(app); break;
    case GUI_NAV_CHAINS:      panel_chains(app); break;
    case GUI_NAV_VPN:         panel_vpn(app); break;
    case GUI_NAV_CONNECTIONS: panel_connections(app); break;
    case GUI_NAV_CHECKER:     panel_checker(app); break;
    case GUI_NAV_LOCKDOWN:    panel_lockdown(app); break;
    case GUI_NAV_SETTINGS:    panel_settings(app); break;
    default: break;
    }
    igEndChild();

    render_confirm(app);

    igEnd();

    if (app->show_demo) {
        igShowDemoWindow(&app->show_demo);
    }
}
