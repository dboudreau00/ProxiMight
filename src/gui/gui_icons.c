#include "gui_icons.h"
#include "gui_backend.h"
#include "gui_imgui.h"

#include <math.h>
#include <stddef.h>
#include <string.h>

#ifndef PMX_PI
#define PMX_PI 3.14159265358979323846f
#endif

static void arc(float cx, float cy, float r, float a0, float a1, unsigned col,
                float thick, int segs) {
    float prevx = cx + r * cosf(a0);
    float prevy = cy + r * sinf(a0);
    for (int i = 1; i <= segs; i++) {
        float a = a0 + (a1 - a0) * ((float)i / (float)segs);
        float x = cx + r * cosf(a);
        float y = cy + r * sinf(a);
        guix_draw_line(prevx, prevy, x, y, col, thick);
        prevx = x;
        prevy = y;
    }
}

void gui_icon(gui_icon_id id, float x, float y, float s, unsigned col) {
    const float cx = x + s * 0.5f;
    const float cy = y + s * 0.5f;
    float t = s * 0.09f;
    if (t < 1.3f) {
        t = 1.3f;
    }

#define L(ax, ay, bx, by) guix_draw_line((ax), (ay), (bx), (by), col, t)
#define DOTF(px, py, r) guix_draw_circle_filled((px), (py), (r), col, 16)

    switch (id) {
    case GUI_ICON_CHAIN:
        guix_draw_chain_mark(cx, cy, s / 38.0f, col, col, 3.2f);
        break;
    case GUI_ICON_LINK: {
        float w = s * 0.44f, h = s * 0.62f;
        guix_draw_rect(cx - w * 0.5f, cy - h * 0.5f, cx + w * 0.5f, cy + h * 0.5f,
                       col, w * 0.5f, t);
        break;
    }
    case GUI_ICON_PLUS:
        L(cx - s * 0.30f, cy, cx + s * 0.30f, cy);
        L(cx, cy - s * 0.30f, cx, cy + s * 0.30f);
        break;
    case GUI_ICON_TRASH:
        L(x + s * 0.18f, y + s * 0.30f, x + s * 0.82f, y + s * 0.30f);
        L(x + s * 0.40f, y + s * 0.30f, x + s * 0.40f, y + s * 0.20f);
        L(x + s * 0.40f, y + s * 0.20f, x + s * 0.60f, y + s * 0.20f);
        L(x + s * 0.60f, y + s * 0.20f, x + s * 0.60f, y + s * 0.30f);
        guix_draw_rect(x + s * 0.26f, y + s * 0.30f, x + s * 0.74f, y + s * 0.82f,
                       col, s * 0.06f, t);
        L(x + s * 0.42f, y + s * 0.40f, x + s * 0.42f, y + s * 0.72f);
        L(x + s * 0.58f, y + s * 0.40f, x + s * 0.58f, y + s * 0.72f);
        break;
    case GUI_ICON_CHECK:
        L(x + s * 0.20f, y + s * 0.52f, x + s * 0.42f, y + s * 0.72f);
        L(x + s * 0.42f, y + s * 0.72f, x + s * 0.80f, y + s * 0.28f);
        break;
    case GUI_ICON_CROSS:
        L(x + s * 0.26f, y + s * 0.26f, x + s * 0.74f, y + s * 0.74f);
        L(x + s * 0.74f, y + s * 0.26f, x + s * 0.26f, y + s * 0.74f);
        break;
    case GUI_ICON_GEAR: {
        guix_draw_circle(cx, cy, s * 0.30f, col, t, 24);
        for (int i = 0; i < 8; i++) {
            float a = (float)i * (PMX_PI / 4.0f);
            L(cx + cosf(a) * s * 0.30f, cy + sinf(a) * s * 0.30f,
              cx + cosf(a) * s * 0.44f, cy + sinf(a) * s * 0.44f);
        }
        DOTF(cx, cy, s * 0.11f);
        break;
    }
    case GUI_ICON_SHIELD:
        L(cx - s * 0.28f, y + s * 0.22f, cx + s * 0.28f, y + s * 0.22f);
        L(cx - s * 0.28f, y + s * 0.22f, cx - s * 0.28f, cy + s * 0.06f);
        L(cx + s * 0.28f, y + s * 0.22f, cx + s * 0.28f, cy + s * 0.06f);
        L(cx - s * 0.28f, cy + s * 0.06f, cx, y + s * 0.82f);
        L(cx + s * 0.28f, cy + s * 0.06f, cx, y + s * 0.82f);
        break;
    case GUI_ICON_POWER:
        guix_draw_circle(cx, cy + s * 0.04f, s * 0.30f, col, t, 24);
        L(cx, y + s * 0.16f, cx, cy + s * 0.02f);
        break;
    case GUI_ICON_DOT:
        DOTF(cx, cy, s * 0.28f);
        break;
    case GUI_ICON_EDIT:
        L(x + s * 0.30f, y + s * 0.70f, x + s * 0.70f, y + s * 0.30f);
        L(x + s * 0.62f, y + s * 0.22f, x + s * 0.78f, y + s * 0.38f);
        L(x + s * 0.62f, y + s * 0.22f, x + s * 0.70f, y + s * 0.30f);
        guix_draw_triangle_filled(x + s * 0.22f, y + s * 0.78f, x + s * 0.30f,
                                  y + s * 0.70f, x + s * 0.34f, y + s * 0.82f,
                                  col);
        break;
    case GUI_ICON_PLAY:
        guix_draw_triangle_filled(x + s * 0.34f, y + s * 0.26f, x + s * 0.34f,
                                  y + s * 0.74f, x + s * 0.76f, cy, col);
        break;
    case GUI_ICON_STOP:
        guix_draw_rect_filled(x + s * 0.30f, y + s * 0.30f, x + s * 0.70f,
                              y + s * 0.70f, col, s * 0.06f);
        break;
    case GUI_ICON_REFRESH: {
        float r = s * 0.30f;
        arc(cx, cy, r, -PMX_PI * 0.35f, PMX_PI * 1.15f, col, t, 20);
        /* arrowhead at the arc start (upper-right) */
        float ax = cx + r * cosf(-PMX_PI * 0.35f);
        float ay = cy + r * sinf(-PMX_PI * 0.35f);
        L(ax, ay, ax - s * 0.14f, ay - s * 0.02f);
        L(ax, ay, ax + s * 0.02f, ay - s * 0.16f);
        break;
    }
    case GUI_ICON_UP:
        L(x + s * 0.28f, y + s * 0.60f, cx, y + s * 0.36f);
        L(x + s * 0.72f, y + s * 0.60f, cx, y + s * 0.36f);
        break;
    case GUI_ICON_DOWN:
        L(x + s * 0.28f, y + s * 0.40f, cx, y + s * 0.64f);
        L(x + s * 0.72f, y + s * 0.40f, cx, y + s * 0.64f);
        break;
    case GUI_ICON_GLOBE:
        guix_draw_circle(cx, cy, s * 0.30f, col, t, 24);
        L(cx - s * 0.30f, cy, cx + s * 0.30f, cy);
        L(cx, cy - s * 0.30f, cx, cy + s * 0.30f);
        arc(cx, cy, s * 0.30f, PMX_PI * 0.5f, PMX_PI * 1.5f, col, t * 0.7f, 12);
        break;
    case GUI_ICON_LOCK:
        guix_draw_rect(cx - s * 0.22f, cy - s * 0.02f, cx + s * 0.22f,
                       y + s * 0.80f, col, s * 0.05f, t);
        arc(cx, cy - s * 0.02f, s * 0.14f, PMX_PI, PMX_PI * 2.0f, col, t, 14);
        DOTF(cx, cy + s * 0.14f, s * 0.045f);
        break;
    case GUI_ICON_GRIP:
        for (int r = 0; r < 3; r++) {
            for (int cc = 0; cc < 2; cc++) {
                DOTF(cx + (cc == 0 ? -s * 0.14f : s * 0.14f),
                     y + s * 0.28f + (float)r * s * 0.22f, s * 0.045f);
            }
        }
        break;
    case GUI_ICON_LIST:
        for (int r = 0; r < 3; r++) {
            float yy = y + s * 0.30f + (float)r * s * 0.20f;
            DOTF(x + s * 0.26f, yy, s * 0.045f);
            L(x + s * 0.38f, yy, x + s * 0.78f, yy);
        }
        break;
    case GUI_ICON_ROUTE:
        guix_draw_circle(x + s * 0.26f, y + s * 0.72f, s * 0.10f, col, t, 14);
        guix_draw_circle(x + s * 0.74f, y + s * 0.28f, s * 0.10f, col, t, 14);
        L(x + s * 0.34f, y + s * 0.64f, x + s * 0.66f, y + s * 0.36f);
        break;
    default:
        break;
    }

#undef L
#undef DOTF
}

void gui_icon_inline(gui_icon_id id, float size, unsigned col) {
    float x = 0, y = 0;
    guix_cursor_screen(&x, &y);
    gui_icon(id, x, y, size, col);
    igDummy(v2(size, size));
}

/* --------------------------------------------------------------------------
 *  Offline rasterizer for the window / taskbar icon.
 *
 *  Same construction as guix_draw_chain_mark(): two stadium-shaped links, each
 *  22x34 units and offset 11 units from the centre, stroked at 3.2 units, with
 *  the right link drawn behind the left and then re-stroked across the lower
 *  overlap so the two read as interlocked. Here it is evaluated per pixel from
 *  a signed distance field instead of through ImDrawList, because an icon is a
 *  bitmap and there is no draw list at start-up.
 * ------------------------------------------------------------------------- */

/* Signed distance to a rounded box centred on the origin: half-extents
 * (hx, hy), corner radius r. Negative inside, zero on the outline. With
 * r == hx the box is a stadium, which is exactly one chain link. */
static float sd_round_box(float px, float py, float hx, float hy, float r) {
    float qx = fabsf(px) - hx + r;
    float qy = fabsf(py) - hy + r;
    float mx = qx > 0.0f ? qx : 0.0f;
    float my = qy > 0.0f ? qy : 0.0f;
    float longest = qx > qy ? qx : qy;
    float inside = longest < 0.0f ? longest : 0.0f;
    return sqrtf(mx * mx + my * my) + inside - r;
}

void gui_icon_chain_rgba(int size, unsigned char *out) {
    if (size <= 0 || out == NULL) {
        return;
    }
    memset(out, 0, (size_t)size * (size_t)size * 4u);

    const float fs = (float)size;
    const float pad = fs * 0.07f;
    /* Floor the stroke so the mark still reads at 16 px, where a straight
     * 3.2-unit scale would land under one pixel. */
    float th = fs * 0.085f;
    if (th < 1.3f) {
        th = 1.3f;
    }
    /* 44 units = the mark's full path width (2 * offset + link width). */
    const float k = (fs - 2.0f * pad - th) / 44.0f;
    const float hw = 11.0f * k; /* half link width  */
    const float hh = 17.0f * k; /* half link height */
    const float ov = 11.0f * k; /* each link's offset from centre */
    const float half_th = th * 0.5f;
    const float cx = fs * 0.5f;
    const float cy = fs * 0.5f;
    /* Where the right link crosses back over the left one. Mirrors the clip
     * rect in guix_draw_chain_mark (cy + full_height * 0.10). */
    const float band_y0 = cy + hh * 0.20f;

    /* Two accent tones, so which link is in front stays readable at 16 px.
     * Front/left #5B9BFF, back/right #2F6FE0 — the theme accent and its dim
     * variant. Spelled in decimal: 0x5Bf would lex as the literal 0x5BF. */
    const float a_r = 91.0f / 255.0f, a_g = 155.0f / 255.0f, a_b = 1.0f;
    const float b_r = 47.0f / 255.0f, b_g = 111.0f / 255.0f, b_b = 224.0f / 255.0f;

    enum { SS = 4 }; /* 4x4 supersampling — the only antialiasing here */
    const float inv_samples = 1.0f / (float)(SS * SS);

    for (int py = 0; py < size; py++) {
        for (int px = 0; px < size; px++) {
            float cov_a = 0.0f, cov_b = 0.0f, cov_band = 0.0f;
            for (int sy = 0; sy < SS; sy++) {
                for (int sx = 0; sx < SS; sx++) {
                    float x = (float)px + ((float)sx + 0.5f) / (float)SS;
                    float y = (float)py + ((float)sy + 0.5f) / (float)SS;
                    /* Ring = the outline of the stadium, half_th either side. */
                    if (fabsf(sd_round_box(x - (cx - ov), y - cy, hw, hh, hw)) <
                        half_th) {
                        cov_a += 1.0f;
                    }
                    if (fabsf(sd_round_box(x - (cx + ov), y - cy, hw, hh, hw)) <
                        half_th) {
                        cov_b += 1.0f;
                        if (y >= band_y0) {
                            cov_band += 1.0f;
                        }
                    }
                }
            }
            if (cov_a <= 0.0f && cov_b <= 0.0f) {
                continue; /* leave it transparent */
            }
            cov_a *= inv_samples;
            cov_b *= inv_samples;
            cov_band *= inv_samples;

            /* "over" compositing, premultiplied: right link, then left link on
             * top, then the right link's lower band back over it. */
            float pr = 0.0f, pg = 0.0f, pb = 0.0f, pa = 0.0f;
#define PMX_OVER(sr, sg, sb, sa)                                               \
    do {                                                                       \
        float _a = (sa);                                                       \
        pr = (sr) * _a + pr * (1.0f - _a);                                      \
        pg = (sg) * _a + pg * (1.0f - _a);                                      \
        pb = (sb) * _a + pb * (1.0f - _a);                                      \
        pa = _a + pa * (1.0f - _a);                                             \
    } while (0)
            PMX_OVER(b_r, b_g, b_b, cov_b);
            PMX_OVER(a_r, a_g, a_b, cov_a);
            PMX_OVER(b_r, b_g, b_b, cov_band);
#undef PMX_OVER

            if (pa <= 0.0f) {
                continue;
            }
            /* GLFW and the ICO format both want straight (un-premultiplied)
             * alpha, so divide the colour back out. */
            unsigned char *p =
                out + ((size_t)py * (size_t)size + (size_t)px) * 4u;
            p[0] = (unsigned char)(pr / pa * 255.0f + 0.5f);
            p[1] = (unsigned char)(pg / pa * 255.0f + 0.5f);
            p[2] = (unsigned char)(pb / pa * 255.0f + 0.5f);
            p[3] = (unsigned char)(pa * 255.0f + 0.5f);
        }
    }
}
