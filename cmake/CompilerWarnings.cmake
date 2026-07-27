# Shared warning configuration. Call pmx_set_warnings(<target> [STRICT]).
#
# Warnings are loud on our own code. PMX_WERROR=ON builds the whole tree — core,
# GUI and all tests — with zero warnings on MSVC, so use it before tagging:
#
#     cmake -S . -B build/werror -G Ninja -DPMX_WERROR=ON && cmake --build build/werror
#
# It stays OFF by default only so that a different compiler or SDK version
# inventing a new warning cannot stop someone from building at all. Third-party
# headers used to make it unusable; they are marked SYSTEM now (see
# cmake/dependencies.cmake and src/gui/CMakeLists.txt), so a warning that appears
# here is genuinely ours.

option(PMX_WERROR "Treat ProxiMight warnings as errors" OFF)

function(pmx_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            /permissive-
            /wd4996   # allow POSIX-ish names / deprecated CRT in scaffold
            /wd4204   # non-constant aggregate initializer (we use C99 idioms)
            # 'APIENTRY': macro redefinition. GLFW's glfw3.h defines APIENTRY when
            # it isn't already defined, then the Windows SDK's minwindef.h defines
            # it again; MSVC reports the collision inside the SDK header. Neither
            # file is ours and the definitions agree, so this is noise — but it is
            # emitted while compiling OUR sources, which SYSTEM includes cannot
            # suppress and which would fail the build under PMX_WERROR.
            /wd4005
        )
        if(PMX_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
        target_compile_definitions(${target} PRIVATE
            _CRT_SECURE_NO_WARNINGS
            WIN32_LEAN_AND_MEAN
            NOMINMAX
        )
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align
            -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter
        )
        if(PMX_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()
