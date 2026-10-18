# Copyright (c) 2026 CyNickal Software LLC
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.25)
project(dma_hello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

set(DMA_LIB_SOURCES
    src/dma_hello/log.cpp
    src/dma_hello/config.cpp
    src/dma_hello/memory.cpp
    src/dma_hello/x64.cpp
    src/dma_hello/pe.cpp
    src/dma_hello/process.cpp
    src/dma_hello/hook.cpp
    src/dma_hello/mm/pfn.cpp
    src/dma_hello/mm/vad.cpp
    src/dma_hello/mm/page_tables.cpp
    src/dma_hello/mm/allocate.cpp
)

add_library(dma_hello_lib STATIC ${DMA_LIB_SOURCES})
target_include_directories(dma_hello_lib PUBLIC src)

add_subdirectory(hello_dll)

add_executable(dma_hello
    src/main.cpp
    src/dma_hello/session.cpp
    src/dma_hello/inject.cpp
)
target_include_directories(dma_hello PRIVATE src deps/MemProcFS)
target_link_directories(dma_hello PRIVATE deps/MemProcFS)
target_link_libraries(dma_hello PRIVATE dma_hello_lib vmm leechcore)
add_dependencies(dma_hello hello_dll beep_dll)

add_executable(dma_hello_tests
    deps/Catch2/catch_amalgamated.cpp
    tests/cpp/test_main.cpp
    tests/cpp/test_x64.cpp
    tests/cpp/test_pte.cpp
    tests/cpp/test_vad.cpp
    tests/cpp/test_pfn.cpp
    tests/cpp/test_page_tables.cpp
    tests/cpp/test_pe.cpp
    tests/cpp/test_hook.cpp
    tests/cpp/test_flow.cpp
    tests/cpp/test_system.cpp
    tests/cpp/test_metrics.cpp
    tests/cpp/test_stochastic.cpp
    tests/cpp/test_pressure.cpp
    tests/cpp/test_config.cpp
    tests/cpp/simulated_memory.cpp
    tests/cpp/test_target_process.cpp
    tests/cpp/test_integration.cpp
)
target_include_directories(dma_hello_tests PRIVATE src tests/cpp deps/Catch2)
target_link_libraries(dma_hello_tests PRIVATE dma_hello_lib)

set_target_properties(dma_hello dma_hello_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin
)

add_custom_command(TARGET dma_hello POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/vmm.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/leechcore.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/FTD3XX.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/FTD3XXWU.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/leechcore_driver.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/dbghelp.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/symsrv.dll
        ${CMAKE_SOURCE_DIR}/deps/MemProcFS/symsrv.yes
        $<TARGET_FILE_DIR:dma_hello>
)
