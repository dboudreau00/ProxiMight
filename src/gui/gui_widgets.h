/*
 * gui_widgets.h — reusable, theme-aware widgets built on cimgui + guix + icons.
 * Panels use these so the whole app looks like one system.
 */
#ifndef PMX_GUI_WIDGETS_H
#define PMX_GUI_WIDGETS_H

#include <stdbool.h>
#include "gui_icons.h"

struct gui_theme;

typedef enum gui_btn_kind {
    GUI_BTN_PRIMARY = 0, /* accent-filled call to action     */
    GUI_BTN_SECONDARY,   /* subtle surface button            */
    GUI_BTN_GHOST,       /* text-only until hovered          */
    GUI_BTN_DANGER       /* destructive                      */
} gui_btn_kind;

void gui_widgets_use_theme(const struct gui_theme *t);
const struct gui_theme *gui_widgets_theme(void);

/* Full custom button (icon optional). `id` must be unique; `label` is drawn. */
bool gui_button(const char *id, gui_icon_id icon, bool has_icon,
                const char *label, gui_btn_kind kind, float min_width);

/* Exactly the width gui_button() will occupy for this label, so a caller can
 * right-align one without guessing. Shares gui_button's metrics, so the two
 * cannot disagree. Only valid while a frame is in progress (it measures text). */
float gui_button_width(const char *label, bool has_icon, float min_width);

/* Convenience wrappers. */
bool gui_primary_button(const char *label, gui_icon_id icon);
bool gui_secondary_button(const char *label, gui_icon_id icon);
bool gui_ghost_button(const char *label, gui_icon_id icon);
bool gui_danger_button(const char *label, gui_icon_id icon);

/* Square icon-only button with a hover tooltip. */
bool gui_icon_button(const char *id, gui_icon_id icon, const char *tooltip,
                     gui_btn_kind kind);

/* iOS-style toggle switch (just the control; add your own label). */
bool gui_toggle(const char *id, bool *value);

/* A rounded pill. Colors are packed IM_COL32. */
void gui_badge(const char *label, unsigned fill, unsigned text_col);
/* A status pill: colored dot + label, tinted by `color` (RGBA float). */
void gui_status_pill(const char *label, const float color[4]);

/* Icon + heading title + optional dim subtitle. */
void gui_section_header(gui_icon_id icon, const char *title,
                        const char *subtitle);

/* A stat tile (icon, big value, small label) of the given width. */
void gui_stat_tile(gui_icon_id icon, const char *label, const char *value,
                   const float accent[4], float width);

/* "(?)" that shows `text` on hover. */
void gui_help_marker(const char *text);

void gui_vspace(float h);

/* ---- form helpers ------------------------------------------------------ */

/* A dim field label (put above an input). */
void gui_field_label(const char *text);
/* Full-width single-line text input. `id` unique; `hint` may be NULL. */
bool gui_input_text(const char *id, const char *hint, char *buf, size_t cap,
                    bool password);
/* Full-width combo over items[0..count). */
bool gui_combo(const char *id, int *current, const char *const *items, int count);
/* Full-width integer input, clamped to [minv, maxv]. */
bool gui_input_int(const char *id, int *value, int minv, int maxv);

/* A bordered card region (a styled child). Pair begin/end; begin returns
 * visibility like igBeginChild. height <= 0 auto-fits to content height. */
bool gui_card_begin(const char *id, float height);
void gui_card_end(void);

/* A tinted note/banner: left accent bar, icon, wrapped text. `color` RGBA. */
void gui_note(gui_icon_id icon, const char *text, const float color[4]);

#endif /* PMX_GUI_WIDGETS_H */
