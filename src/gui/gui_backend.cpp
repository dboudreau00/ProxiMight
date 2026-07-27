// gui_backend.cpp — GLFW + OpenGL3 + Dear ImGui plumbing behind a C API.
//
// This is the ONLY C++ translation unit in the app (besides the imgui core &
// backends). It keeps the C side free of C++ and of cimgui-version ABI quirks.

#include "gui_backend.h"

#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#if defined(_WIN32)
#include <windows.h>
#include <commdlg.h> /* GetOpenFileNameA — windows.h omits it under LEAN_AND_MEAN */
#include <dwmapi.h>  /* DwmSetWindowAttribute — title-bar tinting */
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h> /* glfwGetWin32Window */

/* Present since the Windows 11 SDK; spelled out so an older SDK still builds.
 * DWMWA_USE_IMMERSIVE_DARK_MODE was 19 on Windows 10 builds 18985-19040 and 20
 * from 19041 on — we only send 20, so on those few pre-19041 builds the caption
 * simply stays light instead of us poking an unrelated attribute. */
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif
#endif

#include <cstdio>
#include <cstddef>

namespace {
GLFWwindow *g_window = nullptr;
ImFont *g_font_body = nullptr;
ImFont *g_font_h1 = nullptr;
float g_scale = 1.0f;

void glfw_error_cb(int code, const char *desc) {
    std::fprintf(stderr, "[glfw] error %d: %s\n", code, desc);
}

// Try a few well-known system fonts so the UI looks native instead of the
// pixelated imgui default. Returns true if a TTF was loaded.
bool load_system_fonts(float px_body, float px_h1) {
    ImGuiIO &io = ImGui::GetIO();
    static const char *candidates[] = {
#if defined(_WIN32)
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
#elif defined(__APPLE__)
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
#else
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
#endif
    };
    const char *chosen = nullptr;
    for (const char *path : candidates) {
        std::FILE *f = std::fopen(path, "rb");
        if (f) {
            std::fclose(f);
            chosen = path;
            break;
        }
    }
    if (!chosen) {
        return false;
    }
    g_font_body = io.Fonts->AddFontFromFileTTF(chosen, px_body);
#if defined(_WIN32)
    const char *bold = "C:\\Windows\\Fonts\\segoeuib.ttf";
    std::FILE *bf = std::fopen(bold, "rb");
    if (bf) {
        std::fclose(bf);
        g_font_h1 = io.Fonts->AddFontFromFileTTF(bold, px_h1);
    }
#endif
    if (!g_font_h1) {
        g_font_h1 = io.Fonts->AddFontFromFileTTF(chosen, px_h1);
    }
    return g_font_body != nullptr;
}
} // namespace

extern "C" {

bool guix_init(const char *title, int width, int height) {
    glfwSetErrorCallback(glfw_error_cb);
    if (!glfwInit()) {
        return false;
    }

    const char *glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#if defined(__APPLE__)
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif
    glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);

    g_window = glfwCreateWindow(width, height, title ? title : "ProxiMight",
                                nullptr, nullptr);
    if (!g_window) {
        glfwTerminate();
        return false;
    }
    glfwMakeContextCurrent(g_window);
    glfwSwapInterval(1); // vsync

    float sx = 1.0f, sy = 1.0f;
    glfwGetWindowContentScale(g_window, &sx, &sy);
    g_scale = (sx > 0.0f) ? sx : 1.0f;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr; // don't litter an imgui.ini
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    float px_body = 16.0f * g_scale;
    float px_h1 = 22.0f * g_scale;
    if (!load_system_fonts(px_body, px_h1)) {
        io.Fonts->AddFontDefault();
        g_font_body = nullptr;
        g_font_h1 = nullptr;
    }

    if (!ImGui_ImplGlfw_InitForOpenGL(g_window, true)) {
        return false;
    }
    if (!ImGui_ImplOpenGL3_Init(glsl_version)) {
        return false;
    }
    return true;
}

void guix_shutdown(void) {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    if (g_window) {
        glfwDestroyWindow(g_window);
        g_window = nullptr;
    }
    glfwTerminate();
}

bool guix_should_close(void) {
    return g_window ? glfwWindowShouldClose(g_window) : true;
}
void guix_request_close(void) {
    if (g_window) {
        glfwSetWindowShouldClose(g_window, GLFW_TRUE);
    }
}
void guix_set_window_title(const char *title) {
    if (g_window && title) {
        glfwSetWindowTitle(g_window, title);
    }
}

void guix_set_window_icon(const guix_icon_image *images, int count) {
    if (g_window == nullptr || images == nullptr || count <= 0) {
        return;
    }
#if defined(__APPLE__)
    // GLFW reports GLFW_FEATURE_UNAVAILABLE here (the icon comes from the app
    // bundle), which would just spam glfw_error_cb. Skip it instead.
    (void)images;
    (void)count;
#else
    enum { MAX_IMAGES = 8 };
    GLFWimage imgs[MAX_IMAGES];
    int n = 0;
    for (int i = 0; i < count && n < MAX_IMAGES; i++) {
        if (images[i].rgba == nullptr || images[i].size <= 0) {
            continue;
        }
        imgs[n].width = images[i].size;
        imgs[n].height = images[i].size;
        // GLFW's GLFWimage::pixels is non-const but the data is only read and
        // copied before glfwSetWindowIcon returns, so dropping const is safe.
        imgs[n].pixels = const_cast<unsigned char *>(images[i].rgba);
        n++;
    }
    if (n > 0) {
        glfwSetWindowIcon(g_window, n, imgs);
    }
#endif
}

void guix_set_titlebar_theme(bool dark, unsigned caption, unsigned text,
                             unsigned border) {
#if defined(_WIN32)
    if (g_window == nullptr) {
        return;
    }
    HWND hwnd = glfwGetWin32Window(g_window);
    if (hwnd == nullptr) {
        return;
    }
    // Windows 10 1809+: flips the caption's own text and min/max/close glyphs
    // to their light-on-dark rendering.
    BOOL immersive_dark = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &immersive_dark,
                          sizeof(immersive_dark));

    // Windows 11 22000+: the exact colors, so the caption blends into the app
    // body rather than merely being "a dark title bar". guix_rgba packs
    // 0xAABBGGRR and COLORREF is 0x00BBGGRR, so masking the alpha off converts
    // it. Results are ignored deliberately: on Windows 10 these three return
    // E_INVALIDARG and the immersive-dark call above is the fallback.
    COLORREF cap = (COLORREF)(caption & 0x00FFFFFFu);
    COLORREF txt = (COLORREF)(text & 0x00FFFFFFu);
    COLORREF bdr = (COLORREF)(border & 0x00FFFFFFu);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &cap, sizeof(cap));
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &txt, sizeof(txt));
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &bdr, sizeof(bdr));
#else
    (void)dark;
    (void)caption;
    (void)text;
    (void)border;
#endif
}

void guix_begin_frame(void) {
    glfwPollEvents();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

void guix_end_frame(float r, float g, float b) {
    ImGui::Render();
    int w = 0, h = 0;
    glfwGetFramebufferSize(g_window, &w, &h);
    glViewport(0, 0, w, h);
    glClearColor(r, g, b, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(g_window);
}

bool guix_open_file_dialog(const char *title, const char *filter_label,
                           const char *patterns, char *out, size_t cap) {
    if (out == nullptr || cap == 0) {
        return false;
    }
    out[0] = '\0';
#if defined(_WIN32)
    // Win32 filters are a double-NUL-terminated list of NUL-separated pairs.
    char filter[256];
    size_t n = 0;
    auto put = [&](const char *s) {
        while (*s && n + 2 < sizeof(filter)) {
            filter[n++] = *s++;
        }
        filter[n++] = '\0';
    };
    put(filter_label ? filter_label : "Supported files");
    put(patterns ? patterns : "*.*");
    put("All files");
    put("*.*");
    filter[n++] = '\0';

    char path[1024];
    path[0] = '\0';
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr; /* no native-handle dependency needed */
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = (DWORD)sizeof(path);
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn)) {
        std::snprintf(out, cap, "%s", path);
        return true;
    }
    return false;
#else
    (void)title;
    (void)filter_label;
    (void)patterns;
    return false;
#endif
}

float guix_dpi_scale(void) { return g_scale; }
double guix_time(void) { return glfwGetTime(); }

void guix_push_heading_font(void) {
    if (g_font_h1) {
        // imgui 1.92: PushFont is 2-arg; LegacySize == the size passed to
        // AddFontFromFileTTF (pre-1.92 behavior).
        ImGui::PushFont(g_font_h1, g_font_h1->LegacySize);
    }
}
void guix_pop_font(void) {
    if (g_font_h1) {
        ImGui::PopFont();
    }
}

// ---- geometry ------------------------------------------------------------
void guix_content_avail(float *w, float *h) {
    ImVec2 v = ImGui::GetContentRegionAvail();
    if (w) *w = v.x;
    if (h) *h = v.y;
}
void guix_cursor_screen(float *x, float *y) {
    ImVec2 v = ImGui::GetCursorScreenPos();
    if (x) *x = v.x;
    if (y) *y = v.y;
}
void guix_item_min(float *x, float *y) {
    ImVec2 v = ImGui::GetItemRectMin();
    if (x) *x = v.x;
    if (y) *y = v.y;
}
void guix_item_max(float *x, float *y) {
    ImVec2 v = ImGui::GetItemRectMax();
    if (x) *x = v.x;
    if (y) *y = v.y;
}
void guix_window_pos(float *x, float *y) {
    ImVec2 v = ImGui::GetWindowPos();
    if (x) *x = v.x;
    if (y) *y = v.y;
}
void guix_window_size(float *w, float *h) {
    ImVec2 v = ImGui::GetWindowSize();
    if (w) *w = v.x;
    if (h) *h = v.y;
}
void guix_mouse_pos(float *x, float *y) {
    ImVec2 v = ImGui::GetIO().MousePos;
    if (x) *x = v.x;
    if (y) *y = v.y;
}
void guix_calc_text(const char *text, float *w, float *h) {
    ImVec2 v = ImGui::CalcTextSize(text ? text : "");
    if (w) *w = v.x;
    if (h) *h = v.y;
}

// ---- drawing -------------------------------------------------------------
void guix_draw_line(float x0, float y0, float x1, float y1, unsigned col,
                    float thickness) {
    ImGui::GetWindowDrawList()->AddLine(ImVec2(x0, y0), ImVec2(x1, y1),
                                        (ImU32)col, thickness);
}
void guix_draw_rect(float x0, float y0, float x1, float y1, unsigned col,
                    float rounding, float thickness) {
    // imgui 1.92: AddRect param order is (rounding, thickness, flags).
    ImGui::GetWindowDrawList()->AddRect(ImVec2(x0, y0), ImVec2(x1, y1),
                                        (ImU32)col, rounding, thickness);
}
void guix_draw_rect_filled(float x0, float y0, float x1, float y1, unsigned col,
                           float rounding) {
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1),
                                              (ImU32)col, rounding, 0);
}
void guix_draw_rect_gradient_v(float x0, float y0, float x1, float y1,
                               unsigned col_top, unsigned col_bottom) {
    ImGui::GetWindowDrawList()->AddRectFilledMultiColor(
        ImVec2(x0, y0), ImVec2(x1, y1), (ImU32)col_top, (ImU32)col_top,
        (ImU32)col_bottom, (ImU32)col_bottom);
}
void guix_draw_circle(float cx, float cy, float r, unsigned col, float thickness,
                      int segments) {
    ImGui::GetWindowDrawList()->AddCircle(ImVec2(cx, cy), r, (ImU32)col,
                                          segments, thickness);
}
void guix_draw_circle_filled(float cx, float cy, float r, unsigned col,
                             int segments) {
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(cx, cy), r, (ImU32)col,
                                                segments);
}
void guix_draw_triangle_filled(float x0, float y0, float x1, float y1, float x2,
                               float y2, unsigned col) {
    ImGui::GetWindowDrawList()->AddTriangleFilled(
        ImVec2(x0, y0), ImVec2(x1, y1), ImVec2(x2, y2), (ImU32)col);
}
void guix_draw_triangle(float x0, float y0, float x1, float y1, float x2,
                        float y2, unsigned col, float thickness) {
    ImGui::GetWindowDrawList()->AddTriangle(ImVec2(x0, y0), ImVec2(x1, y1),
                                            ImVec2(x2, y2), (ImU32)col, thickness);
}
void guix_draw_ngon_filled(float cx, float cy, float r, unsigned col, int sides) {
    ImGui::GetWindowDrawList()->AddNgonFilled(ImVec2(cx, cy), r, (ImU32)col,
                                              sides);
}
void guix_draw_text(float x, float y, unsigned col, const char *text) {
    ImGui::GetWindowDrawList()->AddText(ImVec2(x, y), (ImU32)col, text);
}
void guix_draw_text_sized(float x, float y, unsigned col, const char *text,
                          float px) {
    ImFont *font = g_font_h1 ? g_font_h1 : ImGui::GetFont();
    ImGui::GetWindowDrawList()->AddText(font, px, ImVec2(x, y), (ImU32)col, text);
}
void guix_push_clip(float x0, float y0, float x1, float y1, bool intersect) {
    ImGui::GetWindowDrawList()->PushClipRect(ImVec2(x0, y0), ImVec2(x1, y1),
                                             intersect);
}
void guix_pop_clip(void) { ImGui::GetWindowDrawList()->PopClipRect(); }

static void ring_rrect(ImDrawList *dl, float x0, float y0, float x1, float y1,
                       float rounding, ImU32 col, float thick) {
    dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), col, rounding, thick);
}

void guix_draw_chain_mark(float cx, float cy, float scale, unsigned col_a,
                          unsigned col_b, float thickness) {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    const float lw = 22.0f * scale; // link width
    const float lh = 34.0f * scale; // link height
    const float ov = 11.0f * scale; // horizontal offset of each link from center
    const float th = thickness * scale;
    const float rounding = lw * 0.5f;

    const float ax0 = cx - ov - lw * 0.5f, ax1 = cx - ov + lw * 0.5f;
    const float ay0 = cy - lh * 0.5f, ay1 = cy + lh * 0.5f;
    const float bx0 = cx + ov - lw * 0.5f, bx1 = cx + ov + lw * 0.5f;
    const float by0 = cy - lh * 0.5f, by1 = cy + lh * 0.5f;

    // B behind, A in front...
    ring_rrect(dl, bx0, by0, bx1, by1, rounding, (ImU32)col_b, th);
    ring_rrect(dl, ax0, ay0, ax1, ay1, rounding, (ImU32)col_a, th);
    // ...then re-stroke B's left edge over A in the lower overlap so the two
    // links appear interlocked.
    dl->PushClipRect(ImVec2(bx0 - th, cy + lh * 0.10f), ImVec2(ax1 + th, by1 + th),
                     true);
    ring_rrect(dl, bx0, by0, bx1, by1, rounding, (ImU32)col_b, th);
    dl->PopClipRect();
}

} // extern "C"
