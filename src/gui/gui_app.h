/*
 * gui_app.h — application state and the top-level shell.
 *
 * The struct is intentionally public to the GUI translation units so each panel
 * can read/write shared UI state (the active engine, selection, caches). Panels
 * are plain functions declared at the bottom.
 */
#ifndef PMX_GUI_APP_H
#define PMX_GUI_APP_H

#include "proximight/pmx.h"
#include "gui_theme.h"

#define GUI_LOG_CAP 600

typedef enum gui_nav {
    GUI_NAV_DASHBOARD = 0,
    GUI_NAV_PROXIES,
    GUI_NAV_RULES,
    GUI_NAV_CHAINS,
    GUI_NAV_VPN,
    GUI_NAV_CONNECTIONS,
    GUI_NAV_CHECKER,
    GUI_NAV_LOCKDOWN,
    GUI_NAV_SETTINGS,
    GUI_NAV__COUNT
} gui_nav;

typedef struct gui_log_entry {
    int level;
    char text[192];
} gui_log_entry;

typedef struct gui_app {
    pmx_engine *engine;

    gui_theme theme;
    bool dark;

    int nav;

    pmx_id sel_proxy;
    pmx_id sel_chain;
    pmx_id sel_vpn;

    /* Cached tunnel status; querying spawns wg.exe / hits a socket, so it is
     * throttled rather than run every frame. */
    pmx_vpn_status vpn_status;
    pmx_id vpn_status_id;
    uint64_t vpn_status_next_ms;
    bool vpn_status_valid;

    /* Network-path (MTR) scan owned by the checker panel. */
    struct pmx_mtr_job *mtr_job;
    pmx_mtr_result mtr_result;
    bool mtr_have_result;
    char mtr_target[PMX_MAX_HOST];

    /* Latest check result per (proxy_id, hop_index). */
    pmx_check_result checks[128];
    size_t check_count;

    /* Thread-safe log ring, fed by the pmx_log sink. */
    pmx_mutex *log_mutex;
    gui_log_entry log[GUI_LOG_CAP];
    size_t log_head, log_len;
    bool log_autoscroll;

    char profile_path[PMX_MAX_PATH];
    char status_msg[PMX_MAX_MSG];
    uint64_t status_msg_until;

    bool show_demo;

    /* Delete confirmation modal. */
    bool confirm_open;
    int confirm_kind; /* 0 proxy, 1 rule, 2 chain */
    pmx_id confirm_id;
    char confirm_label[PMX_MAX_LABEL];
} gui_app;

gui_app *gui_app_create(pmx_engine *engine);
void gui_app_destroy(gui_app *app);

/* Build the entire UI for one frame. */
void gui_app_frame(gui_app *app);

/* (Re)apply the active theme to imgui + widgets. */
void gui_app_apply_theme(gui_app *app);

/* Background color for the GL clear (matches the theme bg). */
void gui_app_bg(gui_app *app, float *r, float *g, float *b);

/* Transient status line shown in the top bar. */
void gui_app_status(gui_app *app, const char *msg);

/* Save/load the working profile to the default path. */
void gui_app_save(gui_app *app);

/* Check-result cache. */
void gui_app_store_check(gui_app *app, const pmx_check_result *r);
const pmx_check_result *gui_app_find_check(gui_app *app, pmx_id proxy_id,
                                           int hop_index);

/* Ask to delete something (opens the confirm modal). */
void gui_app_request_delete(gui_app *app, int kind, pmx_id id, const char *label);

/* Start an async MTR scan of `host` and switch to the checker panel. */
void gui_app_start_path_scan(gui_app *app, const char *host);

/* ---- panels (one per nav section) ------------------------------------- */
void panel_dashboard(gui_app *app);
void panel_proxies(gui_app *app);
void panel_rules(gui_app *app);
void panel_chains(gui_app *app);
void panel_vpn(gui_app *app);
void panel_connections(gui_app *app);
void panel_checker(gui_app *app);
void panel_lockdown(gui_app *app);
void panel_settings(gui_app *app);

#endif /* PMX_GUI_APP_H */
