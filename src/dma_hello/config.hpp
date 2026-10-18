// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <string>

namespace dma_hello {

struct Settings {
    std::string process = "notepad.exe";
    std::string dll_path = "hello_dll\\hello_dll.dll";
    uint64_t alloc_size = 0x100000;
    uint32_t protection = 0x40; // PAGE_EXECUTE_READWRITE
    std::string device = "fpga://";
    std::string hook_module = "user32.dll";
    std::string hook_function = "PeekMessageW";
    std::string hook_export = "LaunchHello";
    int debug_level = 3;
    std::string log_file = "dma_hello.log";
};

struct ParsedArgs {
    Settings settings;
    bool help = false;
    bool ok = true;
};

// key=value lines. Blank lines and # comments are ignored. Unknown keys throw.
// A missing file throws SessionError.
void apply_settings_file(Settings& settings, const std::string& path);

// --config is applied first. Later flags replace those fields. --help sets help.
// An unknown flag or a flag without a value sets ok to false.
ParsedArgs parse_args(int argc, char** argv);

} // namespace dma_hello
