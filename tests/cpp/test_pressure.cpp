// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/mm/allocate.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "world.hpp"

#include <string>
#include <vector>

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("two hundred fifty six pages map both ends", "[stress]") {
    LogSilence quiet;
    constexpr int kPages = 256;
    auto mem = ready_target(kPages + kTableSlack + 8);
    Target target = mem.find_process("notepad.exe");
    auto allocation = allocate(mem, target, static_cast<uint64_t>(kPages) * kPageSize,
                               kPageExecuteReadWrite);
    REQUIRE(allocation.pages.frames.size() == static_cast<size_t>(kPages));
    auto first = existing_pte_slot(mem, target.cr3, allocation.va);
    auto last = existing_pte_slot(mem, target.cr3, allocation.va + (kPages - 1) * kPageSize);
    REQUIRE(first);
    REQUIRE(last);
    REQUIRE((first->pte & kPteAddrMask) == (allocation.pages.frames.front() << 12));
    REQUIRE((last->pte & kPteAddrMask) == (allocation.pages.frames.back() << 12));
}

TEST_CASE("eight processes each receive a private mapping", "[integration]") {
    LogSilence quiet;
    const char* names[] = {"notepad.exe", "explorer.exe", "chrome.exe", "calc.exe",
                           "cmd.exe",     "dllhost.exe",  "svchost.exe", "runtimebroker.exe"};
    std::vector<uint64_t> bases;
    std::vector<uint64_t> cr3s;
    for (int i = 0; i < 8; ++i) {
        uint64_t cr3 = kCr3 + static_cast<uint64_t>(i) * 0x2000;
        SimulatedMemory mem(make_info(80, static_cast<uint32_t>(0x1000 + i), cr3, names[i]));
        plant_free_list(mem, 80);
        Target target = mem.find_process(names[i]);
        plant_covering_vad(mem, target.eprocess);
        REQUIRE(target.cr3 == cr3);
        auto allocation = allocate(mem, target, 0x4000, kPageExecuteReadWrite);
        REQUIRE(allocation.pages.frames.size() == 4);
        auto slot = existing_pte_slot(mem, target.cr3, allocation.va);
        REQUIRE(slot);
        REQUIRE(slot->pte & kPteP);
        bases.push_back(allocation.va);
        cr3s.push_back(target.cr3);
    }
    REQUIRE(bases.size() == 8);
    for (int i = 1; i < 8; ++i) REQUIRE(cr3s[i] != cr3s[0]);
}
