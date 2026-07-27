# proximight_core — the portable C engine (no GUI, no platform UI deps).
# Other front-ends (a CLI, a service) could link this directly.

set(PMX_CORE_SOURCES
    pmx_error.c
    pmx_log.c
    pmx_net.c
    pmx_thread.c
    pmx_procinfo.c
    pmx_socks.c
    pmx_http_connect.c
    pmx_proxy.c
    pmx_rule.c
    pmx_chain.c
    pmx_profile.c
    pmx_protect.c
    pmx_json.c
    pmx_checker.c
    pmx_netpath.c
    pmx_vpn.c
    pmx_vpn_run.c
    pmx_proc.c
    pmx_lockdown.c
    pmx_relay.c
    pmx_nat.c
    pmx_engine.c
)

# Redirection / firewall backends. The stub is always built and is the default;
# real platform backends compile to safe no-ops unless their SDK is present.
set(PMX_BACKEND_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../backend/backend_stub.c
)
if(WIN32)
    list(APPEND PMX_BACKEND_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../backend/windows/backend_windivert.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../backend/windows/firewall_wfp.c
    )
elseif(APPLE)
    list(APPEND PMX_BACKEND_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../backend/macos/backend_pf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../backend/macos/firewall_pf.c
    )
endif()

add_library(proximight_core STATIC ${PMX_CORE_SOURCES} ${PMX_BACKEND_SOURCES})
add_library(pmx::core ALIAS proximight_core)

target_include_directories(proximight_core
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
            ${cjson_SOURCE_DIR}   # cJSON.h (target's interface include dir isn't reliable across versions)
)

target_link_libraries(proximight_core PRIVATE pmx::cjson)

# Platform networking / firewall system libs.
if(WIN32)
    # ws2_32/iphlpapi: sockets + per-app attribution. crypt32: DPAPI (at-rest
    # profile sealing in pmx_protect.c).
    target_link_libraries(proximight_core PUBLIC ws2_32 iphlpapi crypt32)

    # --- Optional: WinDivert SDK (real per-app connection monitoring) --------
    # We deliberately do NOT bundle the driver: you supply and verify your own
    # copy. Drop the SDK under third_party/windivert (or point PMX_WINDIVERT_DIR
    # at it) and re-run CMake. See docs/SETUP-WINDIVERT.md.
    set(PMX_WINDIVERT_DIR "${CMAKE_SOURCE_DIR}/third_party/windivert"
        CACHE PATH "Root of an extracted WinDivert SDK")
    # Accept every layout a WinDivert zip actually arrives in, and every dir a
    # user plausibly points PMX_WINDIVERT_DIR at. The official release keeps the
    # header in include/ and the .lib in x64/, so pointing at the x64 dir (which
    # SETUP-WINDIVERT.md used to suggest) found the library, missed the header,
    # and fell silently back to the stub backend — the least helpful possible
    # failure. The `..` hints cover exactly that case.
    find_path(WINDIVERT_INCLUDE_DIR windivert.h
        HINTS "${PMX_WINDIVERT_DIR}"
              "${PMX_WINDIVERT_DIR}/include"
              "${PMX_WINDIVERT_DIR}/x64"
              "${PMX_WINDIVERT_DIR}/.."
              "${PMX_WINDIVERT_DIR}/../include"
        NO_DEFAULT_PATH)
    find_library(WINDIVERT_LIBRARY NAMES WinDivert
        HINTS "${PMX_WINDIVERT_DIR}" "${PMX_WINDIVERT_DIR}/x64"
              "${PMX_WINDIVERT_DIR}/lib" "${PMX_WINDIVERT_DIR}/lib/x64"
        NO_DEFAULT_PATH)

    if(WINDIVERT_INCLUDE_DIR AND WINDIVERT_LIBRARY)
        message(STATUS "WinDivert SDK found -> real per-app monitoring enabled")
        message(STATUS "  include: ${WINDIVERT_INCLUDE_DIR}")
        message(STATUS "  library: ${WINDIVERT_LIBRARY}")
        target_include_directories(proximight_core PRIVATE ${WINDIVERT_INCLUDE_DIR})
        target_link_libraries(proximight_core PRIVATE ${WINDIVERT_LIBRARY})
        target_compile_definitions(proximight_core PRIVATE PMX_HAVE_WINDIVERT)

        # WinDivert.dll and WinDivert64.sys must sit next to the executable.
        get_filename_component(_wd_libdir "${WINDIVERT_LIBRARY}" DIRECTORY)
        foreach(_wd_file WinDivert.dll WinDivert64.sys WinDivert32.sys)
            if(EXISTS "${_wd_libdir}/${_wd_file}")
                file(COPY "${_wd_libdir}/${_wd_file}"
                     DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
                message(STATUS "  staged ${_wd_file} next to the executable")
            endif()
        endforeach()
    else()
        # Say WHICH half is missing. Finding one and not the other used to look
        # identical to finding neither, which sent people hunting through a
        # directory that was fine.
        if(WINDIVERT_LIBRARY AND NOT WINDIVERT_INCLUDE_DIR)
            message(WARNING
                "WinDivert: found ${WINDIVERT_LIBRARY} but NOT windivert.h. "
                "Point PMX_WINDIVERT_DIR at the EXTRACTED ROOT of the SDK (the "
                "folder containing include/ and x64/), not at x64/ itself. "
                "Falling back to the stub backend.")
        elseif(WINDIVERT_INCLUDE_DIR AND NOT WINDIVERT_LIBRARY)
            message(WARNING
                "WinDivert: found windivert.h in ${WINDIVERT_INCLUDE_DIR} but no "
                "WinDivert.lib. Make sure you extracted the x64 build. Falling "
                "back to the stub backend.")
        else()
            message(STATUS "WinDivert SDK not found -> using the stub backend "
                           "(see docs/SETUP-WINDIVERT.md to enable real monitoring)")
        endif()
        message(STATUS "  looked under: ${PMX_WINDIVERT_DIR}")
    endif()
elseif(APPLE)
    target_link_libraries(proximight_core PUBLIC "-framework CoreFoundation")
endif()

if(WIN32)
    target_compile_definitions(proximight_core PUBLIC PMX_PLATFORM_WINDOWS=1)
elseif(APPLE)
    target_compile_definitions(proximight_core PUBLIC PMX_PLATFORM_MACOS=1)
else()
    target_compile_definitions(proximight_core PUBLIC PMX_PLATFORM_LINUX=1)
endif()

pmx_set_warnings(proximight_core)
