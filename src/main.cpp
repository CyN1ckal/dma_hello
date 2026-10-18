// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/config.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/inject.hpp"
#include "dma_hello/log.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace dma_hello;

static void usage() {
    std::fprintf(stderr,
                 "dma_hello -- map a PE into a process over FPGA DMA (MemProcFS)\n"
                 "  --process NAME       target process (default notepad.exe)\n"
                 "  --ark                target ArkAscended.exe\n"
                 "  --hello              MessageBox payload (default)\n"
                 "  --beep               MessageBeep payload\n"
                 "  --dll PATH           PE32+ payload; last of --dll, --hello, --beep wins\n"
                 "  --device STR         MemProcFS device (default fpga://)\n"
                 "  --size HEX           bytes (default 0x100000; 0 uses the PE size)\n"
                 "  --protection HEX     page protection (default 0x40)\n"
                 "  --hook-module NAME   default user32.dll\n"
                 "  --hook-function NAME default PeekMessageW\n"
                 "  --export NAME        default LaunchHello\n"
                 "  --config PATH        key=value settings; later flags replace them\n"
                 "  --debug N            0 crit, 1 error, 2 warn, 3 info (default), 4+ debug\n"
                 "  --log-file PATH      default dma_hello.log\n");
}

int main(int argc, char** argv) {
    ParsedArgs args;
    try {
        args = parse_args(argc, argv);
    } catch (const DmaError& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 2;
    }
    if (args.help) {
        usage();
        return 0;
    }
    if (!args.ok) {
        std::fprintf(stderr, "unknown or incomplete argument\n");
        usage();
        return 2;
    }
    Settings s = std::move(args.settings);

    try {
        setup_log(s.debug_level, s.log_file);
        auto result = run(s);
        auto& t = result.target;
        auto& a = result.allocation;
        auto& h = result.hook;
        std::printf("target     %s pid=%u cr3=0x%llx\n", t.name.c_str(), t.pid,
                    static_cast<unsigned long long>(t.cr3));
        std::printf("mapping    0x%llx-0x%llx\n", static_cast<unsigned long long>(a.va),
                    static_cast<unsigned long long>(a.va + a.size));
        std::printf("hook       %s!%s @ 0x%llx\n", s.hook_module.c_str(), h.function.c_str(),
                    static_cast<unsigned long long>(h.address));
        std::printf("           COW pfn=0x%llx PA=0x%llx\n",
                    static_cast<unsigned long long>(h.cow_frame),
                    static_cast<unsigned long long>(h.hook_pa));
        std::printf("stub       0x%llx  trampoline=0x%llx\n",
                    static_cast<unsigned long long>(h.stub_va),
                    static_cast<unsigned long long>(h.trampoline_va));
        std::printf("export     %s\n", s.hook_export.c_str());
        std::printf("interact with the target window to fire the one-shot hook\n");
        return 0;
    } catch (const DmaError& e) {
        LOG_ERROR("%s", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
