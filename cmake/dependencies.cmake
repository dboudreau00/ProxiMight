# Third-party dependencies, fetched at configure time via FetchContent.
#
# First configure needs internet. After that they live under build/_deps and are
# cached. All three are pinned to an exact tag or commit — never a branch — so a
# clean configure produces the same build tomorrow as it did today. Bump only
# after verifying both presets.
#
# What we pull:
#   glfw   - windowing + GL context + input (drag/drop, DPI). Zlib license.
#   cimgui - C API bindings for Dear ImGui, with imgui bundled as a submodule so
#            the C API and the C++ core always match. MIT.
#   cJSON  - profile (de)serialization. MIT.
#
# The Dear ImGui GLFW/OpenGL3 *backends* are compiled directly into the GUI
# target from cimgui's bundled imgui/backends (see src/gui/CMakeLists.txt),
# so we never fight a version mismatch between cimgui and imgui.

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# Everything static: a proxifier should be one self-contained binary.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# ---------------------------------------------------------------- GLFW --------
set(GLFW_BUILD_DOCS      OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS     OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES  OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL         OFF CACHE BOOL "" FORCE)
FetchContent_Declare(glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG        3.4
    GIT_SHALLOW    TRUE
)

# ---------------------------------------------------------------- cJSON -------
set(ENABLE_CJSON_TEST         OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_UTILS        OFF CACHE BOOL "" FORCE)
set(CJSON_BUILD_SHARED_LIBS   OFF CACHE BOOL "" FORCE)
set(ENABLE_TARGET_EXPORT      OFF CACHE BOOL "" FORCE)
set(ENABLE_CUSTOM_COMPILER_FLAGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.18
    GIT_SHALLOW    TRUE
)

# ---------------------------------------------------------------- cimgui ------
# SOURCE_SUBDIR points at a directory with no CMakeLists so MakeAvailable only
# *populates* cimgui (fetches sources + the imgui submodule) without running
# cimgui's own CMake. We build our own tightly-controlled targets from the
# sources in src/gui/CMakeLists.txt.
#
# PINNED TO A COMMIT, not to `master`. cimgui publishes no release tags, and it
# carries Dear ImGui as a submodule — so tracking the branch floated the entire
# GUI toolkit: a clean configure on a different day silently got a different
# imgui, and an upstream push could break the build with no change on our side.
# That is not hypothetical here; an imgui 1.92 API shift (AddRect's argument
# order, 2-arg PushFont, ImGuiChildFlags_Border -> Borders,
# ImGuiCol_NavHighlight -> NavCursor) has already cost a debugging session.
# Pinning the cimgui commit pins its imgui submodule with it.
#
# This commit carries imgui 1.92.8. To move: check out the new cimgui commit,
# confirm both presets build AND the GUI renders (imgui breaks are often visual,
# not compile errors — see docs/GUI-DESIGN.md), then bump the hash here.
#
# No GIT_SHALLOW: it means `--depth 1` on a ref, which cannot fetch an arbitrary
# commit. Trading a slower first configure for a reproducible one.
FetchContent_Declare(cimgui
    GIT_REPOSITORY https://github.com/cimgui/cimgui.git
    GIT_TAG        d298666861ebf00dcfeb2407409931c04e47e33c # cimgui + imgui 1.92.8
    GIT_SUBMODULES_RECURSE TRUE
    SOURCE_SUBDIR  cmake_do_not_configure
)

FetchContent_MakeAvailable(glfw cjson cimgui)

# Normalize the cJSON target name across versions: some expose `cjson`, older
# ones only the object files. Create an alias the rest of the tree can rely on.
if(TARGET cjson AND NOT TARGET pmx::cjson)
    add_library(pmx::cjson ALIAS cjson)
endif()

# GLFW's headers are third-party: its warnings are not ours to fix and must not
# be able to fail our build under PMX_WERROR. FetchContent'd targets don't mark
# their own includes SYSTEM, so do it for them.
if(TARGET glfw)
    get_target_property(_glfw_inc glfw INTERFACE_INCLUDE_DIRECTORIES)
    if(_glfw_inc)
        set_target_properties(glfw PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_glfw_inc}")
    endif()
endif()
if(TARGET cjson)
    get_target_property(_cjson_inc cjson INTERFACE_INCLUDE_DIRECTORIES)
    if(_cjson_inc)
        set_target_properties(cjson PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_cjson_inc}")
    endif()
endif()

# Expose cimgui's populated source dir to the whole project.
set(CIMGUI_SOURCE_DIR "${cimgui_SOURCE_DIR}" CACHE INTERNAL "cimgui source dir")
set(IMGUI_SOURCE_DIR  "${cimgui_SOURCE_DIR}/imgui" CACHE INTERNAL "bundled imgui dir")
