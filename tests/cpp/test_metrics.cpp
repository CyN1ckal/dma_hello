// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/allocate.hpp"
#include "dma_hello/mm/constants.hpp"
#include "metrics.hpp"
#include "world.hpp"

#include <filesystem>
#include <fstream>
#include <string>

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("metrics files record claim, vad, hook, and verify counts", "[integration]") {
    LogSilence quiet;
    RunMetrics metrics;
    constexpr int kClaims = 2;
    {
        auto mem = ready_target(160);
        Target target = mem.find_process("notepad.exe");
        for (int i = 0; i < kClaims; ++i) {
            ++metrics.pfn_attempts;
            auto claimed = allocate_physical_pages(mem, 0x1000);
            if (claimed.frames.size() == 1) ++metrics.pfn_ok;
        }
        metrics.note("pfn claims finished");

        ++metrics.vad_attempts;
        mem.add_vad_range(0x10000, 0x1FFFF);
        try {
            allocate(mem, target, 0x1000, kPageExecuteReadWrite);
        } catch (const AllocationError&) {
            metrics.note("adjacent vad refused");
        }

        auto fresh = ready_target();
        Target hooked = fresh.find_process("notepad.exe");
        auto pe = PeImage::parse(minimal_pe());
        auto allocation = allocate(fresh, hooked, 0x3000, kPageExecuteReadWrite);
        ++metrics.hook_attempts;
        auto hook = install_hook(fresh, hooked, allocation, pe, "user32.dll", "PeekMessageW",
                                 "LaunchHello");
        if (hook.cow_frame != 0) ++metrics.hook_ok;
        metrics.note("hook installed");

        ++metrics.verify_attempts;
        std::vector<uint8_t> payload{9, 8, 7, 6};
        fresh.write_with_verify(0xFFFFF78000002000ull, payload);
        ++metrics.verify_ok;
        metrics.note("write verified");
    }

    auto dir = std::filesystem::temp_directory_path() / "dma_hello_metrics";
    metrics.write_to(dir);
    std::ifstream csv(dir / "pfn-metrics.csv");
    std::string body((std::istreambuf_iterator<char>(csv)), std::istreambuf_iterator<char>());
    REQUIRE(body.find("pfn_claim,2,2") != std::string::npos);
    REQUIRE(body.find("vad_extension,0,1") != std::string::npos);
    REQUIRE(body.find("hook,1,1") != std::string::npos);
    REQUIRE(body.find("write_verify,1,1") != std::string::npos);
    std::ifstream log(dir / "timeline.log");
    std::string timeline((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    REQUIRE(timeline.find("hook installed") != std::string::npos);
    REQUIRE(metrics.pfn_ok * 100 / metrics.pfn_attempts >= 95);
    REQUIRE(metrics.hook_ok == metrics.hook_attempts);
}
