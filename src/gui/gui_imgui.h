/*
 * gui_imgui.h — the one place C files pull in the cimgui C API.
 *
 * Defining CIMGUI_DEFINE_ENUMS_AND_STRUCTS makes cimgui.h emit plain-C structs
 * and enums (instead of including the C++ imgui.h). All C GUI translation units
 * include THIS header, never cimgui.h directly.
 */
#ifndef PMX_GUI_IMGUI_H
#define PMX_GUI_IMGUI_H

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"

/* Tiny value constructors — cimgui takes ImVec2/ImVec4 by value in arguments,
 * which is stable across versions; we only avoid relying on by-value *returns*. */
static inline ImVec2 v2(float x, float y) {
    ImVec2 v;
    v.x = x;
    v.y = y;
    return v;
}
static inline ImVec4 v4(float x, float y, float z, float w) {
    ImVec4 v;
    v.x = x;
    v.y = y;
    v.z = z;
    v.w = w;
    return v;
}

#endif /* PMX_GUI_IMGUI_H */
