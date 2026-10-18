// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "simulated_memory.hpp"
#include "test_target_process.hpp"

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("builder defaults and make_target copy fields", "[integration]") {
    auto info = TargetProcessBuilder{}.build();
    REQUIRE(info.name == "notepad.exe");
    REQUIRE(info.pid == 0x1234);
    REQUIRE(info.cr3 == 0x1A2F3C000ull);
    REQUIRE(info.eprocess == 0xFFFF800000000000ull + 0x1234);

    auto custom = TargetProcessBuilder{}
                      .set_name("calc.exe")
                      .set_pid(0x55)
                      .set_cr3(0x999)
                      .build();
    REQUIRE(custom.eprocess == 0xFFFF800000000000ull + 0x55);
    Target copied = make_target(custom);
    REQUIRE(copied.name == custom.name);
    REQUIRE(copied.pid == custom.pid);
    REQUIRE(copied.cr3 == custom.cr3);
    REQUIRE(copied.eprocess == custom.eprocess);
}

TEST_CASE("planted process resolves", "[integration]") {
    auto info = TargetProcessBuilder{}.build();
    SimulatedMemory mem(info);
    ProcessInfo found = mem.find_process("notepad.exe");
    REQUIRE(found.name == "notepad.exe");
    REQUIRE(found.pid == info.pid);
    REQUIRE(found.cr3 == info.cr3);
    REQUIRE(found.eprocess == info.eprocess);
    REQUIRE_THROWS_AS(mem.find_process("NOTEPAD.EXE"), ProcessNotFound);
    REQUIRE_THROWS_AS(mem.find_process("calc.exe"), ProcessNotFound);
}

TEST_CASE("symbols and missing pfn database", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    REQUIRE(mem.symbol("MmPteBase") == kDefaultPteBase);
    mem.clear_symbol("MmPfnDatabase");
    REQUIRE_FALSE(mem.symbol("MmPfnDatabase").has_value());
    REQUIRE_THROWS_AS(allocate_physical_pages(mem, 0x1000), PfnError);
}

TEST_CASE("export table is case-insensitive", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    REQUIRE(mem.export_addr(0, "USER32.DLL", "MessageBoxA") == 0x7FF812345ABCull);
    REQUIRE(mem.export_addr(0x99, "User32.Dll", "messageboxa") == 0x7FF812345ABCull);
    REQUIRE_THROWS_AS(mem.export_addr(1, "user32.dll", "DoesNotExist"), SessionError);
}

TEST_CASE("vad map returns planted ranges only", "[integration]") {
    auto info = TargetProcessBuilder{}
                    .add_vad_range(0x30000, 0x40000)
                    .add_vad_range(0x10000, 0x20000)
                    .build();
    SimulatedMemory mem(info);
    auto ranges = mem.vad_map(info.pid);
    REQUIRE(ranges.size() == 2);
    REQUIRE(ranges[0] == std::pair<uint64_t, uint64_t>{0x10000, 0x20000});
    REQUIRE(ranges[1] == std::pair<uint64_t, uint64_t>{0x30000, 0x40000});
    REQUIRE(mem.vad_map(info.pid + 1).empty());
}

TEST_CASE("phys map uses size not a fake ram image", "[integration]") {
    SimulatedMemory empty(TargetProcessBuilder{}.build());
    REQUIRE(empty.phys_map().empty());

    auto info = TargetProcessBuilder{}.add_phys_range(0x100000, 0x2000).build();
    SimulatedMemory mem(info);
    auto ranges = mem.phys_map();
    REQUIRE(ranges.size() == 1);
    REQUIRE(ranges[0] == std::pair<uint64_t, uint64_t>{0x100000, 0x2000});
}

TEST_CASE("sparse reads and writes cross a page", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    std::vector<uint8_t> payload(16);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(0x10 + i);
    mem.write(0x10000, payload);
    REQUIRE(mem.read(0x10000, 16) == payload);

    std::vector<uint8_t> cross(16, 0xAB);
    for (size_t i = 0; i < cross.size(); ++i) cross[i] = static_cast<uint8_t>(i + 1);
    mem.write(0x1FF8, cross);
    REQUIRE(mem.read(0x1FF8, 16) == cross);
    REQUIRE(mem.read(0x1FF0, 8) == std::vector<uint8_t>(8, 0));
    REQUIRE(mem.read(0x2008, 8) == std::vector<uint8_t>(8, 0));

    mem.write_with_verify(0x3000, payload);
    REQUIRE(mem.read(0x3000, payload.size()) == payload);
}

TEST_CASE("fail_write_after throws once", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    std::vector<uint8_t> payload{1, 2, 3, 4};
    mem.fail_write_after(0);
    REQUIRE_THROWS_AS(mem.write(0x4000, payload), SessionError);
    REQUIRE(mem.read(0x4000, payload.size()) == std::vector<uint8_t>(payload.size(), 0));
    mem.write(0x4000, payload);
    REQUIRE(mem.read(0x4000, payload.size()) == payload);
}

TEST_CASE("virt2phys uses only explicit translations", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    const uint64_t va = 0x7FF000001234ull;
    const uint64_t pa = 0xABC000ull;
    mem.map_va(va, pa);
    auto got = mem.virt2phys(va);
    REQUIRE(got.has_value());
    REQUIRE(*got == (pa | (va & 0xFFF)));
    REQUIRE_FALSE(mem.virt2phys(0xFFFF800000001000ull).has_value());
    REQUIRE_FALSE(mem.virt2phys(0x8000).has_value());
}

TEST_CASE("pfn types are tagged or zeroed", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    mem.set_pfn_type(0x123, "Active");
    auto types = mem.pfn_types({0x123, 0x124});
    REQUIRE(types[0x123] == "Active");
    REQUIRE(types[0x124] == "Zeroed");
}

TEST_CASE("untagged pfn type follows the location byte", "[integration]") {
    SimulatedMemory mem(TargetProcessBuilder{}.build());
    constexpr uint64_t db_ptr = 0xFFFFF78000001000ull;
    constexpr uint64_t db = 0xFFFFF80000000000ull;
    mem.set_symbol("MmPfnDatabase", db_ptr);
    mem.write_u64(db_ptr, db);
    constexpr uint64_t pfn = 0x200;
    uint8_t active = static_cast<uint8_t>(kActiveAndValid);
    uint8_t free = static_cast<uint8_t>(kFreePageList);
    mem.write(db + pfn * 0x30 + 0x22, std::span<const uint8_t>(&active, 1));
    mem.write(db + (pfn + 1) * 0x30 + 0x22, std::span<const uint8_t>(&free, 1));
    auto types = mem.pfn_types({pfn, pfn + 1, pfn + 2});
    REQUIRE(types[pfn] == "Other");
    REQUIRE(types[pfn + 1] == "Free");
    REQUIRE(types[pfn + 2] == "Zeroed");
    mem.set_pfn_type(pfn, "Active");
    REQUIRE(mem.pfn_types({pfn})[pfn] == "Active");
}
