/*
 * gui_icons.h — small vector icons drawn with the guix_ ImDrawList wrappers.
 *
 * All icons render inside the square [x, y, x+size, y+size] in screen space and
 * are stroked in the given IM_COL32 color. gui_icon_inline() reserves layout
 * space at the current cursor so an icon can sit before a label.
 */
#ifndef PMX_GUI_ICONS_H
#define PMX_GUI_ICONS_H

typedef enum gui_icon_id {
    GUI_ICON_CHAIN = 0, /* the interlocked-links brand mark */
    GUI_ICON_LINK,      /* a single link                    */
    GUI_ICON_PLUS,
    GUI_ICON_TRASH,
    GUI_ICON_CHECK,
    GUI_ICON_CROSS,
    GUI_ICON_GEAR,
    GUI_ICON_SHIELD,
    GUI_ICON_POWER,
    GUI_ICON_DOT,
    GUI_ICON_EDIT,
    GUI_ICON_PLAY,
    GUI_ICON_STOP,
    GUI_ICON_REFRESH,
    GUI_ICON_UP,
    GUI_ICON_DOWN,
    GUI_ICON_GLOBE,
    GUI_ICON_LOCK,
    GUI_ICON_GRIP, /* drag handle (dots) */
    GUI_ICON_LIST,
    GUI_ICON_ROUTE,
    GUI_ICON__COUNT
} gui_icon_id;

/* Draw at an explicit screen position. */
void gui_icon(gui_icon_id id, float x, float y, float size, unsigned col);

/* Draw at the current cursor and advance the layout by `size` (keeps SameLine
 * usable for a following label). Returns nothing. */
void gui_icon_inline(gui_icon_id id, float size, unsigned col);

/* Rasterize the interlocked chain-link brand mark into `out` as `size` x `size`
 * RGBA (4 bytes per pixel, NOT premultiplied, rows top-to-bottom) — the layout
 * glfwSetWindowIcon wants. `out` must have room for size*size*4 bytes.
 *
 * Unlike every other function here this draws no imgui geometry and needs no
 * frame in progress: it evaluates the same proportions offline, so the window
 * and taskbar icon stays in step with the mark the UI paints without a second
 * asset to keep in sync. */
void gui_icon_chain_rgba(int size, unsigned char *out);

#endif /* PMX_GUI_ICONS_H */
