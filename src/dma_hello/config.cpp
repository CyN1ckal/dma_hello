// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/config.hpp"

#include "dma_hello/error.hpp"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

namespace dma_hello {
namespace {

std::string trim(std::string s) {
    auto space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && space(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && space(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

void require_full_number(const char* text, char* end, const char* what) {
    if (!text || text[0] == '\0' || text[0] == '-' || end == text || (end && *end != '\0')) {
        throw SessionError(std::string(what) + " is not a complete number");
    }
}

uint64_t parse_size(const char* text) {
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(text ? text : "", &end, 0);
    require_full_number(text, end, "size");
    if (errno == ERANGE) throw SessionError("size is not a complete number");
    if (value == 0) return 0;
    if (value > 0x7FFFFFFF000ull) throw SessionError("size does not fit a page count");
    return value;
}

uint32_t parse_protection(const char* text) {
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(text ? text : "", &end, 0);
    require_full_number(text, end, "protection");
    if (errno == ERANGE || value > 0xFFFFFFFFul) {
        throw SessionError("protection is not a complete number");
    }
    return static_cast<uint32_t>(value);
}

int parse_debug(const char* text) {
    char* end = nullptr;
    errno = 0;
    long value = std::strtol(text ? text : "", &end, 0);
    require_full_number(text, end, "debug");
    if (errno == ERANGE || value > 2147483647L || value < -2147483647L - 1) {
        throw SessionError("debug is not a complete number");
    }
    return static_cast<int>(value);
}

void set_payload(Settings& s, const std::string& value, int line) {
    if (value == "hello") s.dll_path = "hello_dll\\hello_dll.dll";
    else if (value == "beep") s.dll_path = "hello_dll\\beep_dll.dll";
    else throw SessionError("unknown payload '" + value + "' on line " + std::to_string(line));
}

void set_field(Settings& s, const std::string& key, const std::string& value, int line) {
    if (key == "process") s.process = value;
    else if (key == "dll") s.dll_path = value;
    else if (key == "payload") set_payload(s, value, line);
    else if (key == "device") s.device = value;
    else if (key == "size") s.alloc_size = parse_size(value.c_str());
    else if (key == "protection") s.protection = parse_protection(value.c_str());
    else if (key == "hook_module") s.hook_module = value;
    else if (key == "hook_function") s.hook_function = value;
    else if (key == "export") s.hook_export = value;
    else if (key == "debug") s.debug_level = parse_debug(value.c_str());
    else if (key == "log_file") s.log_file = value;
    else throw SessionError("unknown setting '" + key + "' on line " + std::to_string(line));
}

} // namespace

void apply_settings_file(Settings& settings, const std::string& path) {
    std::ifstream in(path);
    if (!in) throw SessionError("cannot read settings file " + path);
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        line = trim(std::move(line));
        if (line.empty()) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            throw SessionError("settings line " + std::to_string(lineno) + " has no '='");
        }
        set_field(settings, trim(line.substr(0, eq)), trim(line.substr(eq + 1)), lineno);
    }
}

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs out;
    std::string config;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") != 0) continue;
        if (i + 1 >= argc) {
            out.ok = false;
            return out;
        }
        config = argv[++i];
    }
    if (!config.empty()) apply_settings_file(out.settings, config);

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            out.help = true;
            return out;
        }
        if (std::strcmp(argv[i], "--config") == 0) {
            ++i;
            continue;
        }
        auto eat = [&](const char* flag) -> const char* {
            if (std::strcmp(argv[i], flag) != 0) return nullptr;
            if (i + 1 >= argc) return nullptr;
            return argv[++i];
        };
        if (std::strcmp(argv[i], "--ark") == 0) {
            out.settings.process = "ArkAscended.exe";
        } else if (std::strcmp(argv[i], "--hello") == 0) {
            out.settings.dll_path = "hello_dll\\hello_dll.dll";
        } else if (std::strcmp(argv[i], "--beep") == 0) {
            out.settings.dll_path = "hello_dll\\beep_dll.dll";
        } else if (const char* v = eat("--process")) out.settings.process = v;
        else if (const char* v = eat("--dll")) out.settings.dll_path = v;
        else if (const char* v = eat("--device")) out.settings.device = v;
        else if (const char* v = eat("--size")) out.settings.alloc_size = parse_size(v);
        else if (const char* v = eat("--protection")) out.settings.protection = parse_protection(v);
        else if (const char* v = eat("--hook-module")) out.settings.hook_module = v;
        else if (const char* v = eat("--hook-function")) out.settings.hook_function = v;
        else if (const char* v = eat("--export")) out.settings.hook_export = v;
        else if (const char* v = eat("--debug")) out.settings.debug_level = parse_debug(v);
        else if (const char* v = eat("--log-file")) out.settings.log_file = v;
        else {
            out.ok = false;
            return out;
        }
    }
    return out;
}

} // namespace dma_hello
