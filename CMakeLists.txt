cmake_minimum_required(VERSION 3.24)

project(ProxiMight
    VERSION 0.2.0
    DESCRIPTION "A per-application proxifier for Windows & macOS"
    LANGUAGES C CXX
)

# --------------------------------------------------------------------------- #
#  Global settings                                                            #
# --------------------------------------------------------------------------- #
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# The app carries a Win32 ICON resource (src/gui/proximight.rc) so the .exe shows
# the chain-link mark in Explorer. RC isn't in project(LANGUAGES) above because
# it only exists on Windows.
if(WIN32)
    enable_language(RC)
endif()

# One place for the runnable binary + its shared assets.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Position-independent code everywhere (keeps static deps happy).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)

enable_testing()

# --------------------------------------------------------------------------- #
#  Dependencies (FetchContent: glfw, cimgui+imgui, cJSON)                     #
# --------------------------------------------------------------------------- #
include(cmake/dependencies.cmake)

# --------------------------------------------------------------------------- #
#  Subprojects                                                                #
# --------------------------------------------------------------------------- #
add_subdirectory(src/core)     # proximight_core   (portable C engine + backends)
add_subdirectory(src/gui)      # proximight        (the app executable)
add_subdirectory(tests)        # CTest unit tests

# --------------------------------------------------------------------------- #
#  Summary                                                                    #
# --------------------------------------------------------------------------- #
message(STATUS "")
message(STATUS "ProxiMight ${PROJECT_VERSION}")
message(STATUS "  build type      : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C / C++         : ${CMAKE_C_COMPILER_ID} / ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  output dir      : ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "  cimgui source   : ${CIMGUI_SOURCE_DIR}")
message(STATUS "")
