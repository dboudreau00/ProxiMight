#include "gui_theme.h"
#include "gui_imgui.h"
#include "gui_backend.h"

#include <string.h>

static void setc(float dst[4], float r, float g, float b, float a) {
    dst[0] = r;
    dst[1] = g;
    dst[2] = b;
    dst[3] = a;
}

void gui_theme_dark(gui_theme *t) {
    if (t == NULL) {
        return;
    }
    t->dark = true;
    setc(t->bg,        0.055f, 0.067f, 0.086f, 1.0f);
    setc(t->surface,   0.086f, 0.106f, 0.133f, 1.0f);
    setc(t->surface2,  0.114f, 0.141f, 0.180f, 1.0f);
    setc(t->border,    0.165f, 0.196f, 0.239f, 1.0f);
    setc(t->text,      0.902f, 0.929f, 0.953f, 1.0f);
    setc(t->text_dim,  0.616f, 0.655f, 0.702f, 1.0f);
    setc(t->text_faint,0.420f, 0.455f, 0.502f, 1.0f);
    setc(t->accent,    0.298f, 0.553f, 1.000f, 1.0f);
    setc(t->accent_dim,0.184f, 0.435f, 0.878f, 1.0f);
    setc(t->accent_text,1.0f,  1.0f,   1.0f,   1.0f);
    setc(t->ok,        0.247f, 0.725f, 0.314f, 1.0f);
    setc(t->warn,      0.890f, 0.702f, 0.255f, 1.0f);
    setc(t->danger,    0.973f, 0.318f, 0.286f, 1.0f);
}

void gui_theme_light(gui_theme *t) {
    if (t == NULL) {
        return;
    }
    t->dark = false;
    setc(t->bg,        0.961f, 0.969f, 0.980f, 1.0f);
    setc(t->surface,   1.000f, 1.000f, 1.000f, 1.0f);
    setc(t->surface2,  0.933f, 0.949f, 0.969f, 1.0f);
    setc(t->border,    0.835f, 0.859f, 0.890f, 1.0f);
    setc(t->text,      0.106f, 0.141f, 0.188f, 1.0f);
    setc(t->text_dim,  0.333f, 0.376f, 0.431f, 1.0f);
    setc(t->text_faint,0.541f, 0.580f, 0.635f, 1.0f);
    setc(t->accent,    0.184f, 0.435f, 0.878f, 1.0f);
    setc(t->accent_dim,0.141f, 0.337f, 0.722f, 1.0f);
    setc(t->accent_text,1.0f,  1.0f,   1.0f,   1.0f);
    setc(t->ok,        0.122f, 0.616f, 0.341f, 1.0f);
    setc(t->warn,      0.784f, 0.541f, 0.102f, 1.0f);
    setc(t->danger,    0.851f, 0.231f, 0.204f, 1.0f);
}

unsigned gui_theme_u32(const float c[4]) {
    return guix_rgbaf(c[0], c[1], c[2], c[3]);
}
unsigned gui_theme_u32a(const float c[4], float alpha) {
    return guix_rgbaf(c[0], c[1], c[2], alpha);
}

void gui_theme_mix(const float a[4], const float b[4], float t, float out[4]) {
    for (int i = 0; i < 4; i++) {
        out[i] = a[i] + (b[i] - a[i]) * t;
    }
}

static ImVec4 V(const float c[4]) { return v4(c[0], c[1], c[2], c[3]); }
static ImVec4 Va(const float c[4], float a) { return v4(c[0], c[1], c[2], a); }

void gui_theme_apply(const gui_theme *t) {
    if (t == NULL) {
        return;
    }
    /* Start from imgui's own dark/light defaults so every color slot (including
     * version-specific ones like the tab colors) is sane, then override the
     * long-stable slots with our palette. */
    if (t->dark) {
        igStyleColorsDark(NULL);
    } else {
        igStyleColorsLight(NULL);
    }

    ImGuiStyle *st = igGetStyle();
    ImVec4 *c = st->Colors;

    c[ImGuiCol_Text]                 = V(t->text);
    c[ImGuiCol_TextDisabled]         = V(t->text_faint);
    c[ImGuiCol_WindowBg]             = V(t->bg);
    c[ImGuiCol_ChildBg]              = v4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg]              = V(t->surface);
    c[ImGuiCol_Border]               = V(t->border);
    c[ImGuiCol_BorderShadow]         = v4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]              = V(t->surface2);
    c[ImGuiCol_FrameBgHovered]       = Va(t->accent, t->dark ? 0.22f : 0.16f);
    c[ImGuiCol_FrameBgActive]        = Va(t->accent, t->dark ? 0.32f : 0.24f);
    c[ImGuiCol_TitleBg]              = V(t->surface);
    c[ImGuiCol_TitleBgActive]        = V(t->surface);
    c[ImGuiCol_TitleBgCollapsed]     = V(t->surface);
    c[ImGuiCol_MenuBarBg]            = V(t->surface);
    c[ImGuiCol_ScrollbarBg]          = v4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab]        = V(t->border);
    c[ImGuiCol_ScrollbarGrabHovered] = V(t->text_faint);
    c[ImGuiCol_ScrollbarGrabActive]  = V(t->text_dim);
    c[ImGuiCol_CheckMark]            = V(t->accent);
    c[ImGuiCol_SliderGrab]           = V(t->accent);
    c[ImGuiCol_SliderGrabActive]     = V(t->accent_dim);
    c[ImGuiCol_Button]               = Va(t->accent, t->dark ? 0.18f : 0.12f);
    c[ImGuiCol_ButtonHovered]        = Va(t->accent, t->dark ? 0.32f : 0.22f);
    c[ImGuiCol_ButtonActive]         = Va(t->accent, t->dark ? 0.45f : 0.32f);
    c[ImGuiCol_Header]               = Va(t->accent, t->dark ? 0.22f : 0.15f);
    c[ImGuiCol_HeaderHovered]        = Va(t->accent, t->dark ? 0.34f : 0.24f);
    c[ImGuiCol_HeaderActive]         = Va(t->accent, t->dark ? 0.46f : 0.32f);
    c[ImGuiCol_Separator]            = V(t->border);
    c[ImGuiCol_SeparatorHovered]     = V(t->accent);
    c[ImGuiCol_SeparatorActive]      = V(t->accent);
    c[ImGuiCol_ResizeGrip]           = Va(t->accent, 0.20f);
    c[ImGuiCol_ResizeGripHovered]    = Va(t->accent, 0.55f);
    c[ImGuiCol_ResizeGripActive]     = Va(t->accent, 0.85f);
    c[ImGuiCol_TableHeaderBg]        = V(t->surface2);
    c[ImGuiCol_TableBorderStrong]    = V(t->border);
    c[ImGuiCol_TableBorderLight]     = Va(t->border, 0.5f);
    c[ImGuiCol_TableRowBg]           = v4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]        = Va(t->text, t->dark ? 0.03f : 0.03f);
    c[ImGuiCol_TextSelectedBg]       = Va(t->accent, 0.35f);
    c[ImGuiCol_NavCursor]            = V(t->accent);
    c[ImGuiCol_DragDropTarget]       = V(t->accent);

    /* Metrics (DPI-scaled). */
    const float s = guix_dpi_scale();
    st->WindowRounding    = 10.0f * s;
    st->ChildRounding     = 10.0f * s;
    st->FrameRounding     = 7.0f * s;
    st->PopupRounding     = 7.0f * s;
    st->GrabRounding      = 7.0f * s;
    st->ScrollbarRounding = 9.0f * s;
    st->TabRounding       = 7.0f * s;

    st->WindowPadding     = v2(16 * s, 16 * s);
    st->FramePadding      = v2(11 * s, 7 * s);
    st->ItemSpacing       = v2(10 * s, 9 * s);
    st->ItemInnerSpacing  = v2(8 * s, 6 * s);
    st->CellPadding       = v2(9 * s, 7 * s);
    st->IndentSpacing     = 18 * s;
    st->ScrollbarSize     = 13 * s;
    st->GrabMinSize       = 11 * s;

    st->WindowBorderSize  = 1.0f;
    st->ChildBorderSize   = 1.0f;
    st->FrameBorderSize   = 1.0f;
    st->PopupBorderSize   = 1.0f;

    st->WindowTitleAlign  = v2(0.0f, 0.5f);
}
