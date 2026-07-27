/*
 * gui_main.c — process entry point.
 *
 * Wires up logging, the engine, and the GLFW/imgui window, then runs the frame
 * loop: pump the engine, build the UI, render.
 */
#include "proximight/pmx.h"
#include "gui_app.h"
#include "gui_backend.h"
#include "gui_icons.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static void make_dir(const char *path) { CreateDirectoryA(path, NULL); }
#else
#include <sys/stat.h>
#include <sys/types.h>
static void make_dir(const char *path) { mkdir(path, 0700); }
#endif

/* Build "<config-base>/ProxiMight" (+ "/logs"), creating the dirs. Returns the
 * app dir in `out`. */
static void ensure_app_dir(char *out, size_t n) {
#if defined(_WIN32)
    const char *base = getenv("APPDATA");
    const char *sub = "\\ProxiMight";
    const char *logs = "\\ProxiMight\\logs";
#else
    const char *base = getenv("HOME");
    const char *sub = "/.config/proximight";
    const char *logs = "/.config/proximight/logs";
#endif
    if (base == NULL) {
        pmx_strlcpy(out, ".", n);
        return;
    }
    char appdir[PMX_MAX_PATH];
    char logdir[PMX_MAX_PATH];
    snprintf(appdir, sizeof(appdir), "%s%s", base, sub);
    snprintf(logdir, sizeof(logdir), "%s%s", base, logs);
    make_dir(appdir);
    make_dir(logdir);
    pmx_strlcpy(out, appdir, n);
}

/* Give the window the interlocked chain-link brand mark, rasterized at the sizes
 * Windows actually asks for (title bar 16, Alt-Tab 32, large taskbar 48/64). The
 * pixels come from the same geometry the sidebar paints, so there is no separate
 * image asset to drift out of sync. The .exe's own Explorer icon is a different
 * mechanism — that comes from the ICON resource in proximight.rc. */
static void set_window_icon(void) {
    static const int sizes[] = {16, 24, 32, 48, 64};
    const int count = (int)(sizeof(sizes) / sizeof(sizes[0]));
    unsigned char *pixels[5] = {0};
    guix_icon_image images[5];
    int n = 0;

    for (int i = 0; i < count; i++) {
        size_t bytes = (size_t)sizes[i] * (size_t)sizes[i] * 4u;
        unsigned char *buf = (unsigned char *)malloc(bytes);
        if (buf == NULL) {
            break; /* whatever we already built is still usable */
        }
        gui_icon_chain_rgba(sizes[i], buf);
        pixels[n] = buf;
        images[n].size = sizes[i];
        images[n].rgba = buf;
        n++;
    }
    if (n > 0) {
        guix_set_window_icon(images, n); /* copies the pixels */
    }
    for (int i = 0; i < n; i++) {
        free(pixels[i]);
    }
}

/* Map a --log=<level> argument to a level; -1 if unknown. */
static int log_level_from_name(const char *name) {
    static const char *const names[] = {"trace", "debug", "info",
                                        "warn",  "error", "off"};
    for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        if (strcmp(name, names[i]) == 0) {
            return i; /* matches the pmx_log_level enum order */
        }
    }
    return -1;
}

/* Map a --panel=<name> argument to a gui_nav value; -1 if unknown. */
static int panel_from_name(const char *name) {
    static const char *const names[GUI_NAV__COUNT] = {
        "dashboard", "proxies",     "rules",    "chains",
        "vpn",       "connections", "checker",  "lockdown",
        "settings",
    };
    for (int i = 0; i < GUI_NAV__COUNT; i++) {
        if (strcmp(name, names[i]) == 0) {
            return i;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    char appdir[PMX_MAX_PATH];
    ensure_app_dir(appdir, sizeof(appdir));

    char logpath[PMX_MAX_PATH];
#if defined(_WIN32)
    snprintf(logpath, sizeof(logpath), "%s\\logs\\proximight.log", appdir);
#else
    snprintf(logpath, sizeof(logpath), "%s/logs/proximight.log", appdir);
#endif
    /* Scan for --log=<level> before initializing, so the very first lines are
     * captured at the requested verbosity. The redirect path's key evidence
     * ("redirecting ... via", the relay's "established through N hop(s)") is
     * logged at DEBUG, so verifying the packet rewrite needs --log=debug. */
    pmx_log_level level = PMX_LOG_INFO;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--log=", 6) == 0) {
            int lv = log_level_from_name(argv[i] + 6);
            if (lv >= 0) {
                level = (pmx_log_level)lv;
            } else {
                fprintf(stderr,
                        "unknown --log value: %s (use trace|debug|info|warn|"
                        "error|off)\n",
                        argv[i] + 6);
            }
        }
    }
    pmx_log_init(logpath, level);
    PMX_LOGI("%s %s starting", PMX_APP_NAME, PMX_VERSION_STRING);

    pmx_net_init();

    pmx_engine *engine = pmx_engine_create();
    if (engine == NULL) {
        PMX_LOGE("failed to create engine");
        pmx_log_shutdown();
        return 1;
    }

    if (!guix_init("ProxiMight", 1200, 780)) {
        fprintf(stderr, "ProxiMight: failed to create the application window.\n");
        PMX_LOGE("guix_init failed (no window/GL context)");
        pmx_engine_destroy(engine);
        pmx_net_shutdown();
        pmx_log_shutdown();
        return 1;
    }
    set_window_icon();

    gui_app *app = gui_app_create(engine);
    if (app == NULL) {
        guix_shutdown();
        pmx_engine_destroy(engine);
        pmx_net_shutdown();
        pmx_log_shutdown();
        return 1;
    }
    gui_app_apply_theme(app);

    /* Dev/test convenience:
     *   proximight.exe --panel=connections --autostart   */
    bool autostart = false;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--panel=", 8) == 0) {
            int nav = panel_from_name(argv[i] + 8);
            if (nav >= 0) {
                app->nav = nav;
            } else {
                fprintf(stderr, "unknown --panel value: %s\n", argv[i] + 8);
            }
        } else if (strcmp(argv[i], "--autostart") == 0) {
            autostart = true;
        } else if (strncmp(argv[i], "--import-vpn=", 13) == 0) {
            pmx_vpn *nv = NULL;
            pmx_status st = pmx_profile_import_vpn(pmx_engine_profile(engine),
                                                   argv[i] + 13, &nv);
            if (st == PMX_OK && nv != NULL) {
                app->sel_vpn = nv->id;
            } else {
                fprintf(stderr, "could not import VPN config: %s\n", argv[i] + 13);
            }
        } else if (strncmp(argv[i], "--trace=", 8) == 0) {
            gui_app_start_path_scan(app, argv[i] + 8);
        } else if (strcmp(argv[i], "--backend=platform") == 0) {
            pmx_backend *nb = pmx_backend_platform_create();
            if (nb != NULL) {
                pmx_engine_set_backend(engine, nb);
                PMX_LOGI("switched to platform backend '%s' via command line",
                         nb->name);
            }
        }
    }
    if (autostart) {
        pmx_engine_start(engine);
    }

    while (!guix_should_close()) {
        pmx_engine_pump(engine);
        guix_begin_frame();
        gui_app_frame(app);
        float r = 0, g = 0, b = 0;
        gui_app_bg(app, &r, &g, &b);
        guix_end_frame(r, g, b);
    }

    /* Persist the working profile on exit (best effort). */
    pmx_engine_save_profile(engine, app->profile_path);

    /* Tear the engine down FIRST. It owns the backend / checker / relay / VPN
     * worker threads, and those threads log. The log sink points at `app`, and
     * pmx_logv captures (sink, user) under the log mutex but invokes the sink
     * OUTSIDE it — so unregistering the sink cannot stop a call already in
     * flight. Freeing `app` while a worker sits between the capture and the call
     * is a use-after-free. pmx_engine_destroy joins every one of those threads,
     * so after it returns nothing can reach the sink but this thread. */
    pmx_engine_destroy(engine);
    gui_app_destroy(app);
    guix_shutdown();
    pmx_net_shutdown();
    PMX_LOGI("%s exiting", PMX_APP_NAME);
    pmx_log_shutdown();
    return 0;
}
