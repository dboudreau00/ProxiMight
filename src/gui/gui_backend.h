/*
 * gui_backend.h — C interface to the C++ GLFW/OpenGL3/imgui shim (guix_*).
 *
 * The shim owns the window, the GL context, the imgui platform/renderer
 * backends, fonts, and the render loop. It also exposes stable C wrappers for
 * the few imgui calls whose by-value return ABI varies between cimgui versions
 * (geometry getters) and for direct ImDrawList drawing (so the custom
 * chain-link artwork is painted from C without touching cimgui at all).
 *
 * Colors are packed IM_COL32 (0xAABBGGRR). Use guix_rgba / guix_rgbaf.
 */
#ifndef PMX_GUI_BACKEND_H
#define PMX_GUI_BACKEND_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- lifecycle --------------------------------------------------------- */
bool guix_init(const char *title, int width, int height);
void guix_shutdown(void);
bool guix_should_close(void);
void guix_request_close(void);
void guix_set_window_title(const char *title);

/* ---- window icon ------------------------------------------------------- */
/* One square RGBA image: `size` x `size`, 4 bytes per pixel, NOT premultiplied,
 * rows top-to-bottom. See gui_icon_chain_rgba() for the producer. */
typedef struct guix_icon_image {
    int size;
    const unsigned char *rgba;
} guix_icon_image;

/* Give the window its icon (title bar, Alt-Tab, taskbar). Pass several sizes and
 * the platform picks the best fit per surface. The pixels are copied, so the
 * caller may free them as soon as this returns. No-op on platforms where GLFW
 * doesn't support it (macOS takes its icon from the bundle). */
void guix_set_window_icon(const guix_icon_image *images, int count);

/* ---- native title bar -------------------------------------------------- */
/* Ask the OS to recolor its OWN title bar so it matches the app's theme —
 * without this a light caption sits on top of the dark UI. `dark` switches the
 * caption's built-in text/button rendering; the three colors are packed as
 * guix_rgba (0xAABBGGRR) and their alpha is ignored.
 *
 * Best-effort by design: the exact colors need Windows 11 (build 22000+) and
 * `dark` alone needs Windows 10 1809+. Anywhere else this degrades to whatever
 * the OS was already doing rather than failing. */
void guix_set_titlebar_theme(bool dark, unsigned caption, unsigned text,
                             unsigned border);

/* Poll input + start a new imgui frame. */
void guix_begin_frame(void);
/* Render the frame, clearing to the given background color, then present. */
void guix_end_frame(float bg_r, float bg_g, float bg_b);

/* Native "open file" dialog. Returns false if cancelled or unavailable.
 * `patterns` is a semicolon list like "*.ovpn;*.conf". */
bool guix_open_file_dialog(const char *title, const char *filter_label,
                           const char *patterns, char *out, size_t cap);

float guix_dpi_scale(void);  /* content scale of the primary monitor */
double guix_time(void);      /* seconds since start (for animation)  */

/* Heading font (a larger weight) for titles; pair push/pop. */
void guix_push_heading_font(void);
void guix_pop_font(void);

/* ---- geometry getters (stable C wrappers) ----------------------------- */
void guix_content_avail(float *w, float *h);
void guix_cursor_screen(float *x, float *y);
void guix_item_min(float *x, float *y);
void guix_item_max(float *x, float *y);
void guix_window_pos(float *x, float *y);
void guix_window_size(float *w, float *h);
void guix_mouse_pos(float *x, float *y);
void guix_calc_text(const char *text, float *w, float *h);

/* ---- ImDrawList drawing into the current window ----------------------- */
void guix_draw_line(float x0, float y0, float x1, float y1, unsigned col,
                    float thickness);
void guix_draw_rect(float x0, float y0, float x1, float y1, unsigned col,
                    float rounding, float thickness);
void guix_draw_rect_filled(float x0, float y0, float x1, float y1, unsigned col,
                           float rounding);
void guix_draw_rect_gradient_v(float x0, float y0, float x1, float y1,
                               unsigned col_top, unsigned col_bottom);
void guix_draw_circle(float cx, float cy, float r, unsigned col, float thickness,
                      int segments);
void guix_draw_circle_filled(float cx, float cy, float r, unsigned col,
                             int segments);
void guix_draw_triangle_filled(float x0, float y0, float x1, float y1, float x2,
                               float y2, unsigned col);
void guix_draw_triangle(float x0, float y0, float x1, float y1, float x2,
                        float y2, unsigned col, float thickness);
void guix_draw_ngon_filled(float cx, float cy, float r, unsigned col,
                           int sides);
void guix_draw_text(float x, float y, unsigned col, const char *text);
void guix_draw_text_sized(float x, float y, unsigned col, const char *text,
                          float px);
void guix_push_clip(float x0, float y0, float x1, float y1, bool intersect);
void guix_pop_clip(void);

/* The interlocked chain-link brand mark, centered on (cx, cy). */
void guix_draw_chain_mark(float cx, float cy, float scale, unsigned col_a,
                          unsigned col_b, float thickness);

/* ---- color helpers ----------------------------------------------------- */
static inline unsigned guix_rgba(int r, int g, int b, int a) {
    return ((unsigned)(a & 0xFF) << 24) | ((unsigned)(b & 0xFF) << 16) |
           ((unsigned)(g & 0xFF) << 8) | (unsigned)(r & 0xFF);
}
static inline unsigned guix_rgbaf(float r, float g, float b, float a) {
    int ri = (int)(r * 255.0f + 0.5f);
    int gi = (int)(g * 255.0f + 0.5f);
    int bi = (int)(b * 255.0f + 0.5f);
    int ai = (int)(a * 255.0f + 0.5f);
    return guix_rgba(ri, gi, bi, ai);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PMX_GUI_BACKEND_H */
