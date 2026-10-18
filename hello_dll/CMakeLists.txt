# Copyright (c) 2026 CyNickal Software LLC
# SPDX-License-Identifier: MIT

# CRT-free payload. MessageBeep from the target's user32.
# CMAKE_CXX_FLAGS_DEBUG is applied at generate time for this directory, so
# /RTC1 must stay off here. The CRT-using targets keep the parent flags.

foreach(_flag CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
              CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    string(REGEX REPLACE "/RTC[1csu]+" "" ${_flag} "${${_flag}}")
endforeach()
string(REGEX REPLACE "/O[12xd]" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
unset(_flag)

# CMake 4 can also inject /RTC1 through this property.
set(CMAKE_MSVC_RUNTIME_CHECKS "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")

function(add_payload target source output_name)
    add_library(${target} SHARED ${source})
    set_target_properties(${target} PROPERTIES
        PREFIX ""
        OUTPUT_NAME ${output_name}
        MSVC_RUNTIME_LIBRARY ""
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
        LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin
        LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
        ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin
        ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin
    )
    target_compile_options(${target} PRIVATE
        /GS-
        /Oi-
        $<$<CONFIG:Release>:/O1>
        $<$<CONFIG:Debug>:/Od>
    )
    target_link_options(${target} PRIVATE /NODEFAULTLIB /ENTRY:DllMain /INCREMENTAL:NO)
    target_link_libraries(${target} PRIVATE kernel32 user32)
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${target}>
            ${CMAKE_SOURCE_DIR}/hello_dll/${output_name}.dll
    )
endfunction()

add_payload(hello_dll hello_dll.cpp hello_dll)
add_payload(beep_dll beep_dll.cpp beep_dll)
