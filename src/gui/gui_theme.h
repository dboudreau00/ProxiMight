/*
 * gui_theme.h — light & dark palettes and imgui style application.
 *
 * Colors are RGBA floats in [0,1]. Panels read named roles from the active
 * gui_theme and pack them for ImDrawList with gui_theme_u32().
 */
#ifndef PMX_GUI_THEME_H
#define PMX_GUI_THEME_H

#include <stdbool.h>

typedef struct gui_theme {
    bool dark;

    float bg[4];        /* app background (also the GL clear color)   */
    float surface[4];   /* card / panel background                    */
    float surface2[4];  /* elevated surface, hovered rows             */
    float border[4];
    float text[4];
    float text_dim[4];
    float text_faint[4];

    float accent[4];      /* primary chain-steel accent               */
    float accent_dim[4];  /* pressed/secondary accent                 */
    float accent_text[4]; /* text/icon on top of the accent           */

    float ok[4];     /* healthy / direct        */
    float warn[4];   /* caution / failing over  */
    float danger[4]; /* error / block / tripped */
} gui_theme;

void gui_theme_dark(gui_theme *t);
void gui_theme_light(gui_theme *t);

/* Apply colors + rounding/spacing to the current imgui style (DPI-scaled). */
void gui_theme_apply(const gui_theme *t);

/* Pack an RGBA role into an IM_COL32 for guix_draw_* calls. */
unsigned gui_theme_u32(const float c[4]);
unsigned gui_theme_u32a(const float c[4], float alpha);

/* Linear blend a<-b by t in [0,1], into out. */
void gui_theme_mix(const float a[4], const float b[4], float t, float out[4]);

#endif /* PMX_GUI_THEME_H */
