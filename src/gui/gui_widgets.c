#include "gui_widgets.h"
#include "gui_theme.h"
#include "gui_backend.h"
#include "gui_imgui.h"

#include <string.h>
#include <stdio.h>

static const gui_theme *g_theme = NULL;
static const float kWhite[4] = {1.0f, 1.0f, 1.0f, 1.0f};

void gui_widgets_use_theme(const gui_theme *t) { g_theme = t; }
const gui_theme *gui_widgets_theme(void) { return g_theme; }

static unsigned mixpack(const float a[4], const float b[4], float m, float alpha) {
    float o[4];
    gui_theme_mix(a, b, m, o);
    return guix_rgbaf(o[0], o[1], o[2], alpha);
}

/* Button metrics in one place so gui_button() and gui_button_width() can never
 * drift apart — a caller that right-aligns a button needs its exact width. */
static void button_metrics(float *pad_x, float *pad_y, float *gap,
                           float *iconsz) {
    const float s = guix_dpi_scale();
    if (pad_x != NULL) {
        *pad_x = 13.0f * s;
    }
    if (pad_y != NULL) {
        *pad_y = 8.0f * s;
    }
    if (gap != NULL) {
        *gap = 8.0f * s;
    }
    if (iconsz != NULL) {
        *iconsz = 15.0f * s;
    }
}

float gui_button_width(const char *label, bool has_icon, float min_width) {
    float pad_x = 0, gap = 0, iconsz = 0;
    button_metrics(&pad_x, NULL, &gap, &iconsz);
    float tw = 0, th = 0;
    guix_calc_text(label != NULL ? label : "", &tw, &th);
    float w = pad_x * 2.0f + (has_icon ? iconsz + gap : 0.0f) + tw;
    return w < min_width ? min_width : w;
}

bool gui_button(const char *id, gui_icon_id icon, bool has_icon,
                const char *label, gui_btn_kind kind, float min_width) {
    const gui_theme *t = g_theme;
    if (t == NULL) {
        return false;
    }
    const float s = guix_dpi_scale();
    float pad_x = 0, pad_y = 0, gap = 0, iconsz = 0;
    button_metrics(&pad_x, &pad_y, &gap, &iconsz);

    float tw = 0, th = 0;
    guix_calc_text(label, &tw, &th);
    float w = gui_button_width(label, has_icon, min_width);
    float h = (th > iconsz ? th : iconsz) + pad_y * 2;

    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    bool pressed = igInvisibleButton(id, v2(w, h), 0);
    bool hovered = igIsItemHovered(0);
    bool active = igIsItemActive();

    unsigned bg = 0, border = 0, fg = 0;
    switch (kind) {
    case GUI_BTN_PRIMARY:
        bg = active ? gui_theme_u32(t->accent_dim)
                    : (hovered ? mixpack(t->accent, kWhite, 0.14f, 1.0f)
                               : gui_theme_u32(t->accent));
        fg = gui_theme_u32(t->accent_text);
        break;
    case GUI_BTN_SECONDARY:
        bg = active ? gui_theme_u32(t->border)
                    : (hovered ? mixpack(t->surface2, t->accent, 0.14f, 1.0f)
                               : gui_theme_u32(t->surface2));
        border = gui_theme_u32(t->border);
        fg = gui_theme_u32(t->text);
        break;
    case GUI_BTN_GHOST:
        bg = active ? gui_theme_u32a(t->accent, 0.18f)
                    : (hovered ? gui_theme_u32(t->surface2) : 0);
        fg = hovered ? gui_theme_u32(t->text) : gui_theme_u32(t->text_dim);
        break;
    case GUI_BTN_DANGER:
        bg = active ? gui_theme_u32a(t->danger, 0.42f)
                    : (hovered ? gui_theme_u32a(t->danger, 0.26f)
                               : gui_theme_u32a(t->danger, 0.14f));
        border = gui_theme_u32a(t->danger, 0.55f);
        fg = gui_theme_u32(t->danger);
        break;
    }

    const float r = 7.0f * s;
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + w, y0 + h, bg, r);
    }
    if (border != 0) {
        guix_draw_rect(x0, y0, x0 + w, y0 + h, border, r, 1.2f * s);
    }
    float cx = x0 + pad_x;
    float cyc = y0 + h * 0.5f;
    if (has_icon) {
        gui_icon(icon, cx, cyc - iconsz * 0.5f, iconsz, fg);
        cx += iconsz + gap;
    }
    guix_draw_text(cx, cyc - th * 0.5f, fg, label);
    return pressed;
}

bool gui_primary_button(const char *label, gui_icon_id icon) {
    return gui_button(label, icon, true, label, GUI_BTN_PRIMARY, 0);
}
bool gui_secondary_button(const char *label, gui_icon_id icon) {
    return gui_button(label, icon, true, label, GUI_BTN_SECONDARY, 0);
}
bool gui_ghost_button(const char *label, gui_icon_id icon) {
    return gui_button(label, icon, true, label, GUI_BTN_GHOST, 0);
}
bool gui_danger_button(const char *label, gui_icon_id icon) {
    return gui_button(label, icon, true, label, GUI_BTN_DANGER, 0);
}

bool gui_icon_button(const char *id, gui_icon_id icon, const char *tooltip,
                     gui_btn_kind kind) {
    const gui_theme *t = g_theme;
    if (t == NULL) {
        return false;
    }
    const float s = guix_dpi_scale();
    const float sz = 30.0f * s, iconsz = 17.0f * s;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    bool pressed = igInvisibleButton(id, v2(sz, sz), 0);
    bool hovered = igIsItemHovered(0);
    bool active = igIsItemActive();

    unsigned bg = 0, fg = gui_theme_u32(t->text_dim);
    if (kind == GUI_BTN_DANGER) {
        fg = gui_theme_u32(t->danger);
        bg = active ? gui_theme_u32a(t->danger, 0.36f)
                    : (hovered ? gui_theme_u32a(t->danger, 0.22f) : 0);
    } else {
        if (hovered) {
            fg = gui_theme_u32(t->text);
        }
        bg = active ? gui_theme_u32(t->border)
                    : (hovered ? gui_theme_u32(t->surface2) : 0);
    }
    if ((bg >> 24) != 0) {
        guix_draw_rect_filled(x0, y0, x0 + sz, y0 + sz, bg, 7.0f * s);
    }
    gui_icon(icon, x0 + (sz - iconsz) * 0.5f, y0 + (sz - iconsz) * 0.5f, iconsz,
             fg);
    if (hovered && tooltip != NULL && tooltip[0] != '\0') {
        igSetTooltip("%s", tooltip);
    }
    return pressed;
}

bool gui_toggle(const char *id, bool *value) {
    const gui_theme *t = g_theme;
    if (t == NULL || value == NULL) {
        return false;
    }
    const float s = guix_dpi_scale();
    const float w = 42.0f * s, h = 23.0f * s, r = h * 0.5f;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    bool pressed = igInvisibleButton(id, v2(w, h), 0);
    if (pressed) {
        *value = !*value;
    }
    bool on = *value;
    bool hovered = igIsItemHovered(0);

    unsigned track = on ? (hovered ? mixpack(t->accent, kWhite, 0.12f, 1.0f)
                                   : gui_theme_u32(t->accent))
                        : gui_theme_u32(t->surface2);
    guix_draw_rect_filled(x0, y0, x0 + w, y0 + h, track, r);
    if (!on) {
        guix_draw_rect(x0, y0, x0 + w, y0 + h, gui_theme_u32(t->border), r,
                       1.2f * s);
    }
    float knob_r = (h - 6.0f * s) * 0.5f;
    float knob_cx = on ? (x0 + w - r) : (x0 + r);
    unsigned knob = on ? gui_theme_u32(t->accent_text) : gui_theme_u32(t->text_dim);
    guix_draw_circle_filled(knob_cx, y0 + h * 0.5f, knob_r, knob, 20);
    return pressed;
}

void gui_badge(const char *label, unsigned fill, unsigned text_col) {
    const float s = guix_dpi_scale();
    const float px = 8.0f * s, py = 3.0f * s;
    float tw = 0, th = 0;
    guix_calc_text(label, &tw, &th);
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    float w = tw + px * 2, h = th + py * 2;
    guix_draw_rect_filled(x0, y0, x0 + w, y0 + h, fill, h * 0.5f);
    guix_draw_text(x0 + px, y0 + py, text_col, label);
    igDummy(v2(w, h));
}

void gui_status_pill(const char *label, const float color[4]) {
    const gui_theme *t = g_theme;
    const float s = guix_dpi_scale();
    const float dot = 9.0f * s, gap = 7.0f * s;
    float tw = 0, th = 0;
    guix_calc_text(label, &tw, &th);
    float h = th > dot ? th : dot;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    guix_draw_circle_filled(x0 + dot * 0.5f, y0 + h * 0.5f, dot * 0.5f,
                            gui_theme_u32(color), 16);
    unsigned tc = t ? gui_theme_u32(t->text) : 0xFFFFFFFFu;
    guix_draw_text(x0 + dot + gap, y0 + (h - th) * 0.5f, tc, label);
    igDummy(v2(dot + gap + tw, h));
}

void gui_section_header(gui_icon_id icon, const char *title,
                        const char *subtitle) {
    const gui_theme *t = g_theme;
    const float s = guix_dpi_scale();
    guix_push_heading_font();
    float hh = igGetTextLineHeight();
    unsigned accent = t ? gui_theme_u32(t->accent) : 0xFFFFFFFFu;
    gui_icon_inline(icon, hh, accent);
    igSameLine(0, 10.0f * s);
    igTextUnformatted(title, NULL);
    guix_pop_font();
    if (subtitle != NULL && subtitle[0] != '\0') {
        if (t) {
            igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text_dim[0], t->text_dim[1],
                                                    t->text_dim[2], 1.0f));
        }
        igTextUnformatted(subtitle, NULL);
        if (t) {
            igPopStyleColor(1);
        }
    }
}

void gui_stat_tile(gui_icon_id icon, const char *label, const char *value,
                   const float accent[4], float width) {
    const gui_theme *t = g_theme;
    if (t == NULL) {
        return;
    }
    const float s = guix_dpi_scale();
    const float h = 80.0f * s;
    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);
    guix_draw_rect_filled(x0, y0, x0 + width, y0 + h, gui_theme_u32(t->surface),
                          10.0f * s);
    guix_draw_rect(x0, y0, x0 + width, y0 + h, gui_theme_u32(t->border), 10.0f * s,
                   1.0f);
    guix_draw_rect_filled(x0, y0, x0 + 4.0f * s, y0 + h, gui_theme_u32(accent),
                          0.0f);
    gui_icon(icon, x0 + 14.0f * s, y0 + 14.0f * s, 20.0f * s,
             gui_theme_u32(accent));
    guix_draw_text_sized(x0 + 14.0f * s, y0 + 30.0f * s, gui_theme_u32(t->text),
                         value, 24.0f * s);
    guix_draw_text(x0 + 14.0f * s, y0 + h - 22.0f * s, gui_theme_u32(t->text_dim),
                   label);
    igDummy(v2(width, h));
}

void gui_help_marker(const char *text) {
    igTextDisabled("(?)");
    if (igIsItemHovered(0)) {
        igSetTooltip("%s", text);
    }
}

void gui_vspace(float h) { igDummy(v2(0.0f, h)); }

void gui_field_label(const char *text) {
    const gui_theme *t = g_theme;
    if (t != NULL) {
        igPushStyleColor_Vec4(ImGuiCol_Text,
                              v4(t->text_dim[0], t->text_dim[1], t->text_dim[2], 1));
    }
    igTextUnformatted(text, NULL);
    if (t != NULL) {
        igPopStyleColor(1);
    }
}

bool gui_input_text(const char *id, const char *hint, char *buf, size_t cap,
                    bool password) {
    igSetNextItemWidth(-1.0f);
    ImGuiInputTextFlags flags = password ? ImGuiInputTextFlags_Password : 0;
    if (hint != NULL && hint[0] != '\0') {
        return igInputTextWithHint(id, hint, buf, cap, flags, NULL, NULL);
    }
    return igInputText(id, buf, cap, flags, NULL, NULL);
}

bool gui_combo(const char *id, int *current, const char *const *items,
               int count) {
    igSetNextItemWidth(-1.0f);
    return igCombo_Str_arr(id, current, items, count, -1);
}

bool gui_input_int(const char *id, int *value, int minv, int maxv) {
    igSetNextItemWidth(-1.0f);
    bool changed = igInputInt(id, value, 1, 100, 0);
    if (*value < minv) {
        *value = minv;
    }
    if (*value > maxv) {
        *value = maxv;
    }
    return changed;
}

bool gui_card_begin(const char *id, float height) {
    const gui_theme *t = g_theme;
    if (t != NULL) {
        igPushStyleColor_Vec4(ImGuiCol_ChildBg,
                              v4(t->surface[0], t->surface[1], t->surface[2], 1));
        igPushStyleColor_Vec4(ImGuiCol_Border,
                              v4(t->border[0], t->border[1], t->border[2], 1));
    }
    ImGuiChildFlags flags =
        ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding;
    if (height <= 0) {
        flags |= ImGuiChildFlags_AutoResizeY;
    }
    igBeginChild_Str(id, v2(0.0f, height <= 0 ? 0.0f : height), flags, 0);
    /* Always return true. imgui requires EndChild() to be called even when
     * BeginChild() reports the child as culled, and callers use the
     * `if (gui_card_begin(...)) { ... gui_card_end(); }` shape — returning
     * false there would skip gui_card_end() and desync the child stack
     * (symptom: every card after the first renders empty). Content drawn into
     * a culled child is clipped by imgui anyway, and AutoResizeY needs the
     * content emitted in order to measure the height. */
    return true;
}

void gui_card_end(void) {
    igEndChild();
    if (g_theme != NULL) {
        igPopStyleColor(2);
    }
}

void gui_note(gui_icon_id icon, const char *text, const float color[4]) {
    const gui_theme *t = g_theme;
    const float s = guix_dpi_scale();

    float x0 = 0, y0 = 0;
    guix_cursor_screen(&x0, &y0);

    /* Derive a stable, unique id from the text so two notes in the same window
     * don't collide on a shared "##note" id. */
    unsigned h = 2166136261u;
    for (const char *p = text; p != NULL && *p != '\0'; ++p) {
        h = (h ^ (unsigned char)*p) * 16777619u;
    }
    char note_id[32];
    snprintf(note_id, sizeof(note_id), "##note%08x", h);

    igPushStyleColor_Vec4(ImGuiCol_ChildBg,
                          v4(color[0], color[1], color[2], t && t->dark ? 0.12f : 0.10f));
    igPushStyleColor_Vec4(ImGuiCol_Border, v4(color[0], color[1], color[2], 0.45f));
    igBeginChild_Str(note_id, v2(0, 0),
                     ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY |
                         ImGuiChildFlags_AlwaysUseWindowPadding,
                     0);
    float iconsz = 18.0f * s;
    gui_icon_inline(icon, iconsz, gui_theme_u32(color));
    igSameLine(0, 10.0f * s);
    if (t != NULL) {
        igPushStyleColor_Vec4(ImGuiCol_Text, v4(t->text[0], t->text[1], t->text[2], 1));
    }
    igTextWrapped("%s", text);
    if (t != NULL) {
        igPopStyleColor(1);
    }
    igEndChild();
    igPopStyleColor(2);

    /* Left accent bar over the child's left edge. */
    float x1 = 0, y1 = 0;
    guix_item_max(&x1, &y1);
    guix_draw_rect_filled(x0, y0 + 4.0f * s, x0 + 3.5f * s, y1 - 4.0f * s,
                          gui_theme_u32(color), 2.0f * s);
}
