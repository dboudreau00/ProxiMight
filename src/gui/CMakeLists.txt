# The ProxiMight desktop app: Dear ImGui via cimgui, GLFW + OpenGL3.
#
# Language split (honors the "C where possible" goal):
#   - imgui core + cimgui bindings ...... C++  (library, built once below)
#   - imgui GLFW/OpenGL3 backends ........ C++  (compiled into gui_backend shim)
#   - gui_backend.cpp .................... C++  (thin bridge: window + render loop)
#   - everything else (app, theme, icons, C11
#     widgets, panels) ................... C11  (uses cimgui's C API)

find_package(OpenGL REQUIRED)

# --------------------------------------------------------------------------- #
#  cimgui : imgui core + the generated C API, as one static lib.              #
#  We predefine CIMGUI_API / IMGUI_API empty so MSVC emits plain (non-DLL)    #
#  symbols suitable for static linking.                                       #
# --------------------------------------------------------------------------- #
add_library(cimgui STATIC
    ${CIMGUI_SOURCE_DIR}/cimgui.cpp
    ${IMGUI_SOURCE_DIR}/imgui.cpp
    ${IMGUI_SOURCE_DIR}/imgui_draw.cpp
    ${IMGUI_SOURCE_DIR}/imgui_tables.cpp
    ${IMGUI_SOURCE_DIR}/imgui_widgets.cpp
    ${IMGUI_SOURCE_DIR}/imgui_demo.cpp
)
# SYSTEM: cimgui.h and the imgui headers are third-party. Without this their
# warnings arrive inside every one of our translation units at /W4 (cimgui.h
# alone produced ~50), which buries our own and makes PMX_WERROR unusable.
target_include_directories(cimgui SYSTEM PUBLIC
    ${CIMGUI_SOURCE_DIR} ${IMGUI_SOURCE_DIR})
target_compile_definitions(cimgui PUBLIC
    "CIMGUI_API="
    "IMGUI_API="
    IMGUI_DISABLE_OBSOLETE_FUNCTIONS
)
set_target_properties(cimgui PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------- #
#  The application                                                            #
# --------------------------------------------------------------------------- #
set(PMX_GUI_C_SOURCES
    gui_main.c
    gui_app.c
    gui_theme.c
    gui_icons.c
    gui_widgets.c
    panels/panel_dashboard.c
    panels/panel_proxies.c
    panels/panel_rules.c
    panels/panel_chains.c
    panels/panel_vpn.c
    panels/panel_connections.c
    panels/panel_checker.c
    panels/panel_lockdown.c
    panels/panel_settings.c
)

# C++ shim + the imgui platform/renderer backends (compiled here, not in cimgui,
# so they share cimgui's single imgui symbol set).
set(PMX_GUI_CXX_SOURCES
    gui_backend.cpp
    ${IMGUI_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

add_executable(proximight ${PMX_GUI_C_SOURCES} ${PMX_GUI_CXX_SOURCES})

target_include_directories(proximight PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# imgui's own GLFW/OpenGL3 backend headers — third-party, same reasoning as above.
target_include_directories(proximight SYSTEM PRIVATE ${IMGUI_SOURCE_DIR}/backends)

target_link_libraries(proximight PRIVATE
    pmx::core
    cimgui
    glfw
    OpenGL::GL
)

pmx_set_warnings(proximight)

# Ship a console alongside the window in Debug (logs), hide it in Release.
if(WIN32)
    # The ICON resource: gives proximight.exe the chain-link mark in Explorer,
    # on shortcuts and for the pinned taskbar entry. (The in-window/Alt-Tab icon
    # is set separately at run time — see set_window_icon() in gui_main.c.)
    target_sources(proximight PRIVATE proximight.rc)

    # Release builds use the WINDOWS subsystem so no console flashes up. MSVC
    # then looks for WinMain(), but we have a portable main() — point the entry
    # point back at the CRT's main startup rather than writing a second entry.
    set_target_properties(proximight PROPERTIES
        WIN32_EXECUTABLE $<CONFIG:RelWithDebInfo,Release>
    )
    target_link_options(proximight PRIVATE
        $<$<CONFIG:RelWithDebInfo,Release>:/ENTRY:mainCRTStartup>
    )
    target_link_libraries(proximight PRIVATE dwmapi comdlg32) # title bar + file dialog
endif()

if(APPLE)
    target_link_libraries(proximight PRIVATE
        "-framework Cocoa" "-framework IOKit" "-framework CoreVideo"
    )
endif()
