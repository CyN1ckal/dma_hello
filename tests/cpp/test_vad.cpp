// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/vad.hpp"
#include "fake_memory.hpp"
#include "world.hpp"

#include <cstring>
#include <span>

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("forbidden kuser") {
    REQUIRE(forbidden_range(0x7FFE0000, 0x1000));
    REQUIRE(forbidden_range(0x7FFE7000, 0x100000));
    REQUIRE_FALSE(forbidden_range(0x100000000ull, 0x100000));
}

TEST_CASE("prefer adjacent") {
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{0x10000, 0x1FFFF}, {0x400000, 0x40FFFF}};
    auto adj = prefer_adjacent(ranges, 0x100000);
    REQUIRE(adj);
    auto [hole, start, end] = *adj;
    REQUIRE(end == 0x1FFFF);
    REQUIRE(hole == 0x20000);
}

TEST_CASE("skip high user32 region") {
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{0x7FF80000, 0x7FF80FFF}};
    REQUIRE_FALSE(prefer_adjacent(ranges, 0x1000));
}

TEST_CASE("skip kuser predecessor") {
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{0x7FFE6000, 0x7FFE6FFF}};
    REQUIRE_FALSE(prefer_adjacent(ranges, 0x100000));
}

TEST_CASE("first gap skips kuser neighborhood") {
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{0x10000, 0x1FFFF}, {0x7FFE6000, 0x7FFE6FFF}};
    auto hole = first_gap(ranges, 0x100000);
    REQUIRE(hole);
    REQUIRE(*hole != 0x7FFE7000);
    REQUIRE_FALSE(forbidden_range(*hole, 0x100000));
}

TEST_CASE("candidates keep the later adjacent hole") {
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{0x10000, 0x1FFFF}, {0x300000, 0x30FFFF}};
    auto candidates = vad_candidates(ranges, 0x1000);
    REQUIRE(candidates.size() == 2);
    REQUIRE(candidates[0].adjacent);
    REQUIRE(candidates[0].base_va == 0x20000);
    REQUIRE(candidates[1].adjacent);
    REQUIRE(candidates[1].base_va == 0x310000);
}

TEST_CASE("a size past the user range adds no fallback") {
    REQUIRE(vad_candidates({}, 0x0000800000000000ull).empty());
}

TEST_CASE("empty ranges first user hole") {
    REQUIRE(first_gap({}, 0x1000) == 0x10000);
}

TEST_CASE("adjacent hole refuses a missing MMVAD") {
    class RangeMemory : public KernelMemory {
    public:
        std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override {
            return {{0x10000, 0x1FFFF}};
        }
    } mem;
    ClaimedPages pages;
    pages.page_count = 1;
    Target target;
    target.pid = 4;
    REQUIRE_THROWS_AS(choose_and_extend(mem, target, pages), AllocationError);
}

TEST_CASE("underscored mmvad short supplies the ending vpn") {
    LogSilence quiet;
    auto info = TargetProcessBuilder{}.add_vad_range(0x10000, 0x1FFFF).build();
    SimulatedMemory mem(info);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpn", 0x18);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpn", 0x1C);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpnHigh", 0x20);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpnHigh", 0x21);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Left", 0);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Right", 8);
    constexpr uint64_t kNode = 0xFFFFF80000001000ull;
    mem.write_u64(info.eprocess + 0x38, kNode);
    uint32_t start_vpn = 0x10;
    uint32_t end_vpn = 0x1F;
    mem.write(kNode + 0x18, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&start_vpn), 4));
    mem.write(kNode + 0x1C, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&end_vpn), 4));
    ClaimedPages pages;
    pages.page_count = 1;
    Target target = mem.find_process("notepad.exe");
    auto span = choose_and_extend(mem, target, pages);
    REQUIRE(span.node == kNode);
    REQUIRE(span.base_va == 0x20000);
    auto written = mem.read(kNode + 0x1C, 4);
    REQUIRE(written.size() == 4);
    uint32_t now = 0;
    std::memcpy(&now, written.data(), 4);
    REQUIRE(now == 0x20);
}

uint64_t qword_at(Memory& mem, uint64_t addr) {
    auto raw = mem.read_u64(addr);
    REQUIRE(raw);
    return *raw;
}

uint32_t dword_at(Memory& mem, uint64_t addr) {
    auto raw = mem.read(addr, 4);
    REQUIRE(raw.size() == 4);
    uint32_t value = 0;
    std::memcpy(&value, raw.data(), 4);
    return value;
}

TEST_CASE("private commit charges pages and pagefile bytes") {
    LogSilence quiet;
    auto info = TargetProcessBuilder{}.add_vad_range(0x10000, 0x1FFFF).build();
    SimulatedMemory mem(info);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpn", 0x18);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpn", 0x1C);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpnHigh", 0x20);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpnHigh", 0x21);
    mem.set_field_offset("_MMVAD_SHORT", "CommitCharge", 0x34);
    mem.set_field_offset("_MMVAD_SHORT", "CommitChargeHigh", 0x22);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Left", 0);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Right", 8);
    mem.set_field_offset("_EPROCESS", "CommitCharge", 0x3d8);
    mem.set_field_offset("_EPROCESS", "CommitChargePeak", 0x3e0);
    mem.set_field_offset("_EPROCESS", "NumberOfPrivatePages", 0x288);
    mem.set_field_offset("_EPROCESS", "VirtualSize", 0x228);
    mem.set_field_offset("_EPROCESS", "PeakVirtualSize", 0x220);
    mem.set_field_offset("_EPROCESS", "QuotaBlock", 0x2f8);
    mem.set_field_offset("_EPROCESS", "CommitChargeJob", 0x278);
    mem.set_type_size("_EPROCESS_QUOTA_ENTRY", 0x20);
    mem.set_field_offset("_EPROCESS_QUOTA_ENTRY", "Usage", 0);
    mem.set_field_offset("_EPROCESS_QUOTA_ENTRY", "Peak", 0x10);

    constexpr uint64_t kNode = 0xFFFFF80000001000ull;
    constexpr uint64_t kQuota = 0xFFFFF80000002000ull;
    constexpr uint64_t kSystem = 0xFFFFF80000003000ull;
    mem.write_u64(info.eprocess + 0x38, kNode);
    uint32_t start_vpn = 0x10;
    uint32_t end_vpn = 0x1F;
    uint32_t vad_commit = 7;
    uint8_t commit_high = 0;
    mem.write(kNode + 0x18, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&start_vpn), 4));
    mem.write(kNode + 0x1C, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&end_vpn), 4));
    mem.write(kNode + 0x34, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&vad_commit), 4));
    mem.write(kNode + 0x22, std::span<const uint8_t>(&commit_high, 1));
    mem.write_u64(info.eprocess + 0x3d8, 20);
    mem.write_u64(info.eprocess + 0x3e0, 20);
    mem.write_u64(info.eprocess + 0x288, 20);
    mem.write_u64(info.eprocess + 0x228, 20ull * kPageSize);
    mem.write_u64(info.eprocess + 0x220, 20ull * kPageSize);
    mem.write_u64(info.eprocess + 0x2f8, kQuota);
    mem.write_u64(info.eprocess + 0x278, 0);
    mem.write_u64(info.eprocess + 0x200, 0x1111222233334444ull);
    mem.write_u64(kQuota + 0x40, 9ull * kPageSize);
    mem.write_u64(kQuota + 0x50, 9ull * kPageSize);
    mem.set_symbol("MmTotalCommittedPages", kSystem);
    mem.write_u64(kSystem, 40);

    Target target = mem.find_process("notepad.exe");
    REQUIRE(vad_covering(mem, target, 0x18000) == kNode);
    REQUIRE(vad_covering(mem, target, 0x20000) == 0);

    charge_private_commit(mem, target, kNode, 4, true);
    REQUIRE(dword_at(mem, kNode + 0x34) == 11);
    REQUIRE(mem.read(kNode + 0x22, 1).at(0) == 0);
    REQUIRE(qword_at(mem, info.eprocess + 0x3d8) == 24);
    REQUIRE(qword_at(mem, info.eprocess + 0x3e0) == 24);
    REQUIRE(qword_at(mem, info.eprocess + 0x288) == 24);
    REQUIRE(qword_at(mem, info.eprocess + 0x228) == 24ull * kPageSize);
    REQUIRE(qword_at(mem, info.eprocess + 0x220) == 24ull * kPageSize);
    REQUIRE(qword_at(mem, kQuota + 0x40) == 13ull * kPageSize);
    REQUIRE(qword_at(mem, kQuota + 0x50) == 13ull * kPageSize);
    REQUIRE(qword_at(mem, kSystem) == 44);
    REQUIRE(qword_at(mem, info.eprocess + 0x200) == 0x1111222233334444ull);

    charge_private_commit(mem, target, kNode, 1, false);
    REQUIRE(dword_at(mem, kNode + 0x34) == 12);
    REQUIRE(qword_at(mem, info.eprocess + 0x3d8) == 25);
    REQUIRE(qword_at(mem, info.eprocess + 0x288) == 25);
    REQUIRE(qword_at(mem, info.eprocess + 0x228) == 24ull * kPageSize);
    REQUIRE(qword_at(mem, kQuota + 0x40) == 14ull * kPageSize);
    REQUIRE(qword_at(mem, kSystem) == 45);
    REQUIRE(qword_at(mem, info.eprocess + 0x200) == 0x1111222233334444ull);
}

TEST_CASE("missing commit offsets leave the process image alone") {
    LogSilence quiet;
    auto info = TargetProcessBuilder{}.build();
    SimulatedMemory mem(info);
    mem.write_u64(info.eprocess + 0x3d8, 0x55);
    mem.write_u64(info.eprocess + 0x200, 0x1111222233334444ull);
    Target target = mem.find_process("notepad.exe");
    charge_private_commit(mem, target, 0, 4, true);
    REQUIRE(qword_at(mem, info.eprocess + 0x3d8) == 0x55);
    REQUIRE(qword_at(mem, info.eprocess + 0x200) == 0x1111222233334444ull);
}

TEST_CASE("non-adjacent hole still allocates without a VAD node") {
    class RangeMemory : public KernelMemory {
    public:
        std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override { return {}; }
    } mem;
    ClaimedPages pages;
    pages.page_count = 1;
    Target target;
    REQUIRE_THROWS_WITH(choose_and_extend(mem, target, pages),
                        "no adjacent VAD can cover the range");
}
