// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "fake_memory.hpp"
#include "world.hpp"

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("cow copies and retargets this cr3") {
    PhysMemory s;
    uint64_t cr3 = 0x1000, va = 0x7FFE0000, oldf = 0x5000, newf = 0x6000;
    std::vector<uint8_t> payload(kPageSize, 'A');
    s.plant_4k(cr3, va, oldf, payload, {0x10, 0x11, 0x12});
    auto staged = stage_cow_page(s, cr3, va, newf);
    REQUIRE(staged.pt_pfn > 0);
    auto before = existing_pte_slot(s, cr3, va);
    REQUIRE(before);
    REQUIRE(((before->pte >> 12) & ((1ull << 40) - 1)) == oldf);
    publish_cow_pte(s, staged);
    auto copy = s.read(newf << 12, kPageSize, true);
    REQUIRE(copy == payload);
    auto orig = s.read(oldf << 12, kPageSize, true);
    REQUIRE(orig == payload);
    auto slot = existing_pte_slot(s, cr3, va);
    REQUIRE(slot);
    REQUIRE(((slot->pte >> 12) & ((1ull << 40) - 1)) == newf);
    REQUIRE(slot->pte & kPteP);
    REQUIRE(slot->pte & kPteRw);

    std::vector<uint8_t> b(kPageSize, 'B');
    s.write(newf << 12, b, true);
    REQUIRE(s.read(oldf << 12, kPageSize, true) == payload);
}

TEST_CASE("cow missing pte") {
    PhysMemory s;
    REQUIRE_THROWS_AS(stage_cow_page(s, 0x1000, 0x123000, 0x6000), MappingError);
}

TEST_CASE("virt to phys and write_process_va") {
    PhysMemory s;
    uint64_t cr3 = 0x1000, va = 0x7FFE0000, oldf = 0x5000;
    std::vector<uint8_t> payload(kPageSize, 'A');
    s.plant_4k(cr3, va, oldf, payload, {0x10, 0x11, 0x12});
    REQUIRE(virt_to_phys(s, cr3, va + 0x10) == ((oldf << 12) | 0x10));
    uint8_t zz[2] = {'Z', 'Z'};
    write_process_va(s, cr3, va + 0x10, std::span<const uint8_t>(zz, 2), 0);
    REQUIRE(s.read((oldf << 12) | 0x10, 2, true) == std::vector<uint8_t>({'Z', 'Z'}));
}

namespace {

constexpr uint64_t kPfnDb = 0x90000000;

ClaimedPages claim_for(int pages, std::vector<uint64_t> frames, std::vector<uint64_t> tables) {
    ClaimedPages claimed;
    claimed.page_count = pages;
    claimed.frames = std::move(frames);
    claimed.table_frames = std::move(tables);
    claimed.spare = claimed.table_frames;
    claimed.pfn_database = kPfnDb;
    claimed.layout.size = 0x30;
    return claimed;
}

uint64_t used_entries(PhysMemory& mem, uint64_t pfn) {
    auto u1 = mem.read_u64(kPfnDb + pfn * 0x30);
    REQUIRE(u1);
    return (*u1 >> kUsedPteShift) & kUsedPteMask;
}

uint64_t share_count(PhysMemory& mem, uint64_t pfn) {
    auto u2 = mem.read_u64(kPfnDb + pfn * 0x30 + 0x18);
    REQUIRE(u2);
    return *u2 & kShareCountMask;
}

uint64_t share_flags(PhysMemory& mem, uint64_t pfn) {
    auto u2 = mem.read_u64(kPfnDb + pfn * 0x30 + 0x18);
    REQUIRE(u2);
    return *u2 & ~kShareCountMask;
}

uint32_t ref_count(PhysMemory& mem, uint64_t pfn) {
    auto bytes = mem.read(kPfnDb + pfn * 0x30 + 0x20, 2);
    REQUIRE(bytes.size() == 2);
    return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8);
}

void plant_charges(PhysMemory& mem, uint64_t pfn, uint64_t used, uint64_t share, uint32_t ref,
                   uint64_t share_high = 0) {
    mem.write_u64(kPfnDb + pfn * 0x30, (used << kUsedPteShift) | 1, true);
    mem.write_u64(kPfnDb + pfn * 0x30 + 0x18, (share & kShareCountMask) | share_high, true);
    uint8_t rb[2] = {static_cast<uint8_t>(ref & 0xFF), static_cast<uint8_t>((ref >> 8) & 0xFF)};
    mem.write(kPfnDb + pfn * 0x30 + 0x20, std::span<const uint8_t>(rb, 2));
    uint8_t flags5[4] = {};
    store_le(flags5, uint32_t{1u << kPageTableLinkedBit});
    mem.write(kPfnDb + pfn * 0x30 + kPfnFlags5, std::span<const uint8_t>(flags5, 4));
}

uint64_t original_used(PhysMemory& mem, uint64_t pfn) {
    auto pte = mem.read_u64(kPfnDb + pfn * 0x30 + 0x10);
    REQUIRE(pte);
    return (*pte >> kOrigUsedShift) & kUsedPteMask;
}

void link_table(PhysMemory& mem, uint64_t table_pa, int index, uint64_t child_pa) {
    mem.write_u64(table_pa + static_cast<uint64_t>(index) * 8,
                  child_pa | kPteP | kPteRw | kPteUs | kPteNx, true);
}

} // namespace

TEST_CASE("existing page table used count grows by the new leaves") {
    LogSilence quiet;
    PhysMemory mem;
    constexpr uint64_t kCr3Pa = 0x3000;
    constexpr uint64_t kPdpt = 0x30000;
    constexpr uint64_t kPd = 0x31000;
    constexpr uint64_t kPt = 0x32000;
    constexpr uint64_t kVa = 0x400000;
    link_table(mem, kCr3Pa, 0, kPdpt);
    link_table(mem, kPdpt, 0, kPd);
    link_table(mem, kPd, 2, kPt);
    plant_charges(mem, 0x32, 5, 3, 1, 3ull << 62);
    auto claimed = claim_for(4, {0x100, 0x101, 0x102, 0x103}, {0x200});
    map_range(mem, kCr3Pa, claimed, kVa, kPageExecuteReadWrite);
    REQUIRE(used_entries(mem, 0x32) == 9);
    REQUIRE(share_count(mem, 0x32) == 7);
    REQUIRE((mem.read_u64(kCr3Pa, true).value() & kPteNx) == 0);
    REQUIRE((mem.read_u64(kPdpt, true).value() & kPteNx) == 0);
    REQUIRE((mem.read_u64(kPd + 16, true).value() & kPteNx) == 0);
    REQUIRE(share_flags(mem, 0x32) == (3ull << 62));
    REQUIRE(ref_count(mem, 0x32) == 1);
    REQUIRE((mem.read_u64(kPfnDb + 0x32 * 0x30).value() & 1) == 1);
    REQUIRE(used_entries(mem, 0x100) == 0);
    REQUIRE(share_count(mem, 0x100) == 1);
    REQUIRE(ref_count(mem, 0x100) == 1);
    REQUIRE(mem.read_u64(kPfnDb + 0x100 * 0x30 + 0x10).value() == (6ull << 5));
    REQUIRE(claimed.table_frames.size() == 1);
}

TEST_CASE("new page table records how many entries were published") {
    LogSilence quiet;
    PhysMemory mem;
    constexpr uint64_t kCr3Pa = 0x3000;
    auto claimed = claim_for(3, {0x100, 0x101, 0x102}, {0x200, 0x201, 0x202, 0x203});
    uint8_t modified = 0x1F;
    mem.write(kPfnDb + 0x100 * 0x30 + 0x22, std::span<const uint8_t>(&modified, 1));
    plant_charges(mem, kCr3Pa >> 12, 0, 2, 1);
    map_range(mem, kCr3Pa, claimed, 0x10000, kPageExecuteReadWrite);
    REQUIRE(claimed.table_frames.size() == 1);
    REQUIRE(claimed.table_frames[0] == 0x203);
    REQUIRE(original_used(mem, 0x200) == 1);
    REQUIRE(original_used(mem, 0x201) == 1);
    REQUIRE(original_used(mem, 0x202) == 3);
    REQUIRE(used_entries(mem, 0x202) == 0);
    REQUIRE(share_count(mem, 0x202) == 4);
    REQUIRE(ref_count(mem, 0x202) == 1);
    REQUIRE(share_count(mem, 0x201) == 2);
    REQUIRE(ref_count(mem, 0x201) == 1);
    REQUIRE(share_count(mem, 0x200) == 2);
    REQUIRE(ref_count(mem, 0x200) == 1);
    REQUIRE(share_count(mem, kCr3Pa >> 12) == 3);
    REQUIRE(ref_count(mem, kCr3Pa >> 12) == 1);
    auto pte_addr = mem.read_u64(kPfnDb + 0x200 * 0x30 + 8);
    REQUIRE(pte_addr);
    REQUIRE(*pte_addr == table_entry_kernel_va(mem, 0x10000, 3));
    REQUIRE(mem.read(kPfnDb + 0x100 * 0x30 + 0x22, 1).at(0) ==
            static_cast<uint8_t>(kActiveAndValid | (1 << 6)));
    REQUIRE((mem.read_u64(kPfnDb + 0x202 * 0x30 + 0x10).value() & ~(kUsedPteMask << kOrigUsedShift)) ==
            (4ull << 5));
    REQUIRE(used_entries(mem, kCr3Pa >> 12) == 1);
    REQUIRE(used_entries(mem, 0x100) == 0);
}

TEST_CASE("a present pte in the next page table is refused before any write") {
    LogSilence quiet;
    PhysMemory mem;
    constexpr uint64_t kCr3Pa = 0x3000;
    constexpr uint64_t kPdpt = 0x30000;
    constexpr uint64_t kPd = 0x31000;
    constexpr uint64_t kPt = 0x32000;
    constexpr uint64_t kNextPt = 0x33000;
    // 0x5FE000 is PTE index 510 of the 2 MiB page at 0x400000. Four pages
    // spill across 0x600000, which is the first slot of the next table.
    constexpr uint64_t kVa = 0x5FE000;
    link_table(mem, kCr3Pa, 0, kPdpt);
    link_table(mem, kPdpt, 0, kPd);
    link_table(mem, kPd, 2, kPt);
    link_table(mem, kPd, 3, kNextPt);
    mem.write_u64(kNextPt, (0x40ull << 12) | kPteP | kPteRw | kPteUs, true);
    mem.write_u64(kPfnDb + 0x32 * 0x30, 5ull << kUsedPteShift, true);
    auto claimed = claim_for(4, {0x100, 0x101, 0x102, 0x103}, {0x200});
    REQUIRE(range_block(mem, kCr3Pa, kVa, 4) == RangeBlock::Present);
    REQUIRE_THROWS_WITH(map_range(mem, kCr3Pa, claimed, kVa, kPageExecuteReadWrite),
                        "PTE already present; not stealing");
    REQUIRE(mem.read_u64(kPt + 510 * 8, true).value_or(1) == 0);
    REQUIRE((mem.read_u64(kNextPt, true).value() & kPteAddrMask) == (0x40ull << 12));
    REQUIRE(used_entries(mem, 0x32) == 5);
    REQUIRE(claimed.table_frames.size() == 1);
}

TEST_CASE("a spill into an empty next page table updates both used counts") {
    LogSilence quiet;
    PhysMemory mem;
    constexpr uint64_t kCr3Pa = 0x3000;
    constexpr uint64_t kPdpt = 0x30000;
    constexpr uint64_t kPd = 0x31000;
    constexpr uint64_t kPt = 0x32000;
    constexpr uint64_t kVa = 0x5FE000;
    link_table(mem, kCr3Pa, 0, kPdpt);
    link_table(mem, kPdpt, 0, kPd);
    link_table(mem, kPd, 2, kPt);
    plant_charges(mem, 0x31, 1, 4, 1);
    plant_charges(mem, 0x32, 5, 3, 1);
    auto claimed = claim_for(4, {0x100, 0x101, 0x102, 0x103}, {0x200});
    map_range(mem, kCr3Pa, claimed, kVa, kPageExecuteReadWrite);
    REQUIRE(used_entries(mem, 0x32) == 7);
    REQUIRE(share_count(mem, 0x32) == 5);
    REQUIRE(ref_count(mem, 0x32) == 1);
    REQUIRE(used_entries(mem, 0x31) == 2);
    REQUIRE(share_count(mem, 0x31) == 5);
    REQUIRE(ref_count(mem, 0x31) == 1);
    REQUIRE(original_used(mem, 0x200) == 2);
    REQUIRE(used_entries(mem, 0x200) == 0);
    REQUIRE(share_count(mem, 0x200) == 3);
    REQUIRE(ref_count(mem, 0x200) == 1);
    REQUIRE(claimed.table_frames.empty());
    auto crossed = existing_pte_slot(mem, kCr3Pa, 0x600000);
    REQUIRE(crossed);
    REQUIRE(crossed->pte & kPteP);
}

TEST_CASE("a non-executable mapping leaves parent NX set") {
    LogSilence quiet;
    PhysMemory mem;
    constexpr uint64_t kCr3Pa = 0x3000;
    constexpr uint64_t kPdpt = 0x30000;
    constexpr uint64_t kPd = 0x31000;
    constexpr uint64_t kPt = 0x32000;
    constexpr uint64_t kVa = 0x400000;
    link_table(mem, kCr3Pa, 0, kPdpt);
    link_table(mem, kPdpt, 0, kPd);
    link_table(mem, kPd, 2, kPt);
    plant_charges(mem, 0x32, 5, 3, 1);
    auto claimed = claim_for(1, {0x100}, {});
    map_range(mem, kCr3Pa, claimed, kVa, 0x04);
    REQUIRE((mem.read_u64(kCr3Pa, true).value() & kPteNx) != 0);
    REQUIRE((mem.read_u64(kPdpt, true).value() & kPteNx) != 0);
    REQUIRE((mem.read_u64(kPd + 16, true).value() & kPteNx) != 0);
    auto leaf = existing_pte_slot(mem, kCr3Pa, kVa);
    REQUIRE(leaf);
    REQUIRE(leaf->pte & kPteNx);
}

TEST_CASE("pte kernel va shift mask") {
    PhysMemory s;
    uint64_t va = 0x1000;
    auto got = pte_kernel_va(s, va);
    REQUIRE(got == kDefaultPteBase + ((va >> 9) & 0x7FFFFFFFF8ull));
    REQUIRE(got == kDefaultPteBase + 8);
    s.symbols["MmPteBase"] = 0;
    REQUIRE_THROWS_WITH(pte_kernel_va(s, va), "MmPteBase is unavailable");
}
