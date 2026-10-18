// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/config.hpp"
#include "dma_hello/error.hpp"

#include <filesystem>
#include <fstream>

using namespace dma_hello;

static std::filesystem::path write_settings(const std::string& body) {
    auto path = std::filesystem::temp_directory_path() / "dma_hello_settings.txt";
    std::ofstream out(path);
    out << body;
    return path;
}

TEST_CASE("settings file overrides defaults and flags win") {
    auto path = write_settings(
        "# sample\n"
        "\n"
        "process = explorer.exe\n"
        "dll = payload.dll\n"
        "device = fpga://algo=0\n"
        "size = 0x2000\n"
        "hook_module = USER32.DLL\n"
        "hook_function = MessageBoxA\n"
        "export = LaunchHello\n"
        "debug = 1\n"
        "log_file = run.log\n"
        "protection = 0x04\n");
    Settings file_only;
    apply_settings_file(file_only, path.string());
    REQUIRE(file_only.process == "explorer.exe");
    REQUIRE(file_only.dll_path == "payload.dll");
    REQUIRE(file_only.alloc_size == 0x2000);
    REQUIRE(file_only.protection == 0x04);
    REQUIRE(file_only.debug_level == 1);
    REQUIRE(file_only.hook_function == "MessageBoxA");

    const char* argv[] = {"dma_hello", "--config", path.string().c_str(), "--process", "chrome.exe"};
    auto parsed = parse_args(5, const_cast<char**>(argv));
    REQUIRE(parsed.ok);
    REQUIRE_FALSE(parsed.help);
    REQUIRE(parsed.settings.process == "chrome.exe");
    REQUIRE(parsed.settings.dll_path == "payload.dll");
    REQUIRE(parsed.settings.device == "fpga://algo=0");
}

TEST_CASE("settings file rejects an unknown key and a missing file") {
    auto path = write_settings("nope = 1\n");
    Settings s;
    REQUIRE_THROWS_AS(apply_settings_file(s, path.string()), SessionError);
    REQUIRE_THROWS_AS(apply_settings_file(s, "C:\\no\\such\\dma_hello_settings.txt"), SessionError);
}

TEST_CASE("ark flag targets ArkAscended.exe") {
    const char* argv[] = {"dma_hello", "--ark"};
    auto parsed = parse_args(2, const_cast<char**>(argv));
    REQUIRE(parsed.ok);
    REQUIRE(parsed.settings.process == "ArkAscended.exe");

    const char* notepad_after[] = {"dma_hello", "--ark", "--process", "notepad.exe"};
    auto notepad = parse_args(4, const_cast<char**>(notepad_after));
    REQUIRE(notepad.ok);
    REQUIRE(notepad.settings.process == "notepad.exe");

    const char* ark_after[] = {"dma_hello", "--process", "notepad.exe", "--ark"};
    auto ark = parse_args(4, const_cast<char**>(ark_after));
    REQUIRE(ark.ok);
    REQUIRE(ark.settings.process == "ArkAscended.exe");
}

TEST_CASE("hello and beep select the payload") {
    Settings defaults;
    REQUIRE(defaults.dll_path == "hello_dll\\hello_dll.dll");

    const char* beep_argv[] = {"dma_hello", "--beep"};
    auto beep = parse_args(2, const_cast<char**>(beep_argv));
    REQUIRE(beep.ok);
    REQUIRE(beep.settings.dll_path == "hello_dll\\beep_dll.dll");

    const char* hello_after[] = {"dma_hello", "--beep", "--hello"};
    auto hello = parse_args(3, const_cast<char**>(hello_after));
    REQUIRE(hello.settings.dll_path == "hello_dll\\hello_dll.dll");

    const char* dll_after[] = {"dma_hello", "--beep", "--dll", "other.dll"};
    auto dll = parse_args(4, const_cast<char**>(dll_after));
    REQUIRE(dll.settings.dll_path == "other.dll");

    const char* beep_after[] = {"dma_hello", "--dll", "other.dll", "--beep"};
    auto beep_last = parse_args(4, const_cast<char**>(beep_after));
    REQUIRE(beep_last.settings.dll_path == "hello_dll\\beep_dll.dll");

    auto path = write_settings("payload = beep\n");
    Settings from_file;
    apply_settings_file(from_file, path.string());
    REQUIRE(from_file.dll_path == "hello_dll\\beep_dll.dll");

    auto bad = write_settings("payload = box\n");
    Settings rejected;
    REQUIRE_THROWS_AS(apply_settings_file(rejected, bad.string()), SessionError);
}

TEST_CASE("size protection and debug require a complete number") {
    const char* zero[] = {"dma_hello", "--size", "0"};
    auto pe_sized = parse_args(3, const_cast<char**>(zero));
    REQUIRE(pe_sized.ok);
    REQUIRE(pe_sized.settings.alloc_size == 0);

    const char* prot[] = {"dma_hello", "--protection", "0x20"};
    auto page = parse_args(3, const_cast<char**>(prot));
    REQUIRE(page.ok);
    REQUIRE(page.settings.protection == 0x20);

    const char* negative[] = {"dma_hello", "--size", "-1"};
    REQUIRE_THROWS_AS(parse_args(3, const_cast<char**>(negative)), SessionError);
    const char* junk[] = {"dma_hello", "--size", "0x1000xyz"};
    REQUIRE_THROWS_AS(parse_args(3, const_cast<char**>(junk)), SessionError);
    const char* huge[] = {"dma_hello", "--size", "0x800000000000"};
    REQUIRE_THROWS_AS(parse_args(3, const_cast<char**>(huge)), SessionError);
    const char* debug_junk[] = {"dma_hello", "--debug", "3abc"};
    REQUIRE_THROWS_AS(parse_args(3, const_cast<char**>(debug_junk)), SessionError);

    auto bad = write_settings("size = 12abc\n");
    Settings rejected;
    REQUIRE_THROWS_AS(apply_settings_file(rejected, bad.string()), SessionError);
}

TEST_CASE("parse_args reports help and unknown flags") {
    const char* help_argv[] = {"dma_hello", "--help"};
    auto help = parse_args(2, const_cast<char**>(help_argv));
    REQUIRE(help.help);

    const char* bad_argv[] = {"dma_hello", "--nope"};
    auto bad = parse_args(2, const_cast<char**>(bad_argv));
    REQUIRE_FALSE(bad.ok);
}
