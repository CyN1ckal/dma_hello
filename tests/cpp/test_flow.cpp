// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/allocate.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/pe.hpp"
#include "world.hpp"

#include <cstring>
#include <unordered_map>
#include <vector>

using namespace dma_hello;
using namespace dma_hello::test;

TEST_CASE("simulated injection maps the image and hooks", "[integration]") {
    LogSilence quiet;
    auto mem = ready_target();
    Target target = mem.find_process("notepad.exe");
    auto pe = PeImage::parse(minimal_pe());
    auto allocation = allocate(mem, target, 0x3000, kPageExecuteReadWrite);
    REQUIRE(allocation.va == 0x10000);
    REQUIRE(allocation.size == 0x3000);
    REQUIRE(allocation.pages.frames.size() == 3);

    auto mapped = pe.mapped(allocation.va);
    write_image(mem, target, allocation.va, mapped);
    auto mz = mem.read(allocation.va, 2, false, target.pid);
    REQUIRE(mz.size() == 2);
    REQUIRE(mz[0] == 'M');
    REQUIRE(mz[1] == 'Z');

    resolve_imports(mem, target, allocation.va, pe);
    auto hook = install_hook(mem, target, allocation, pe, "user32.dll", "PeekMessageW",
                             "LaunchHello");
    REQUIRE(hook.address == kHookVa);
    REQUIRE(hook.stolen >= 14);
    REQUIRE(hook.stub_va >= allocation.va + 0x2000);
    REQUIRE(hook.stub_va < allocation.va + allocation.size);

    auto slot = existing_pte_slot(mem, target.cr3, kHookVa);
    REQUIRE(slot);
    REQUIRE((slot->pte & kPteAddrMask) == (hook.cow_frame << 12));
    auto orig = mem.read(kHookFrame << 12, 32, true);
    REQUIRE(orig == std::vector<uint8_t>(32, 0x90));
}

void plant_present(Memory& mem, uint64_t cr3, uint64_t va, uint64_t frame,
                   std::vector<uint64_t> tables) {
    auto idx = [](uint64_t addr, int shift) { return static_cast<int>((addr >> shift) & 0x1FF); };
    uint64_t pml4 = cr3 & kPteAddrMask;
    auto ensure = [&](uint64_t table_pa, int index) {
        uint64_t slot = table_pa + static_cast<uint64_t>(index) * 8;
        uint64_t entry = mem.read_u64(slot, true).value_or(0);
        if (entry & kPteP) return entry & kPteAddrMask;
        uint64_t pfn = tables.front();
        tables.erase(tables.begin());
        std::vector<uint8_t> zero(kPageSize, 0);
        mem.write(pfn << 12, zero, true);
        mem.write_u64(slot, (pfn << 12) | kPteP | kPteRw | kPteUs | kPteNx, true);
        return pfn << 12;
    };
    uint64_t pdpt = ensure(pml4, idx(va, 39));
    uint64_t pd = ensure(pdpt, idx(va, 30));
    uint64_t pt = ensure(pd, idx(va, 21));
    mem.write_u64(pt + static_cast<uint64_t>(idx(va, 12)) * 8,
                  (frame << 12) | kPteP | kPteRw | kPteUs, true);
}

void write_u32(Memory& mem, uint64_t addr, uint32_t value) {
    mem.write(addr, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&value), 4));
}

TEST_CASE("a present pte is refused before any frame is claimed", "[integration]") {
    LogSilence quiet;
    auto mem = ready_target();
    Target target = mem.find_process("notepad.exe");
    plant_present(mem, target.cr3, 0x10000, 0x40, {0x20, 0x21, 0x22});
    auto before = mem.read_u64(kListHead);
    REQUIRE_THROWS_WITH(allocate(mem, target, 0x3000, kPageExecuteReadWrite),
                        "no VAD hole with clear page tables");
    REQUIRE(mem.read_u64(kListHead) == before);
    auto slot = existing_pte_slot(mem, target.cr3, 0x10000);
    REQUIRE(slot);
    REQUIRE((slot->pte & kPteAddrMask) == (0x40ull << 12));
}

TEST_CASE("a later clear hole is used when the first one has a present pte", "[integration]") {
    LogSilence quiet;
    auto info = make_info(200);
    info.vad_ranges.push_back({0x10000, 0x1FFFF});
    info.vad_ranges.push_back({0x300000, 0x30FFFF});
    SimulatedMemory mem(info);
    plant_free_list(mem, 200);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpn", 0x18);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpn", 0x1C);
    mem.set_field_offset("_MMVAD_SHORT", "StartingVpnHigh", 0x20);
    mem.set_field_offset("_MMVAD_SHORT", "EndingVpnHigh", 0x21);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Left", 0);
    mem.set_field_offset("_RTL_BALANCED_NODE", "Right", 8);
    constexpr uint64_t kNode = 0xFFFFF78000004000ull;
    constexpr uint64_t kNext = 0xFFFFF78000005000ull;
    mem.write_u64(info.eprocess + 0x38, kNode);
    mem.write_u64(kNode + 8, kNext);
    write_u32(mem, kNode + 0x18, 0x10);
    write_u32(mem, kNode + 0x1C, 0x1F);
    write_u32(mem, kNext + 0x18, 0x300);
    write_u32(mem, kNext + 0x1C, 0x30F);
    Target target = mem.find_process("notepad.exe");
    plant_present(mem, target.cr3, 0x20000, 0x40, {0x20, 0x21, 0x22});
    auto allocation = allocate(mem, target, 0x1000, kPageExecuteReadWrite);
    REQUIRE(allocation.va == 0x310000);
    REQUIRE(allocation.vad_node == kNext);
    auto dirty = existing_pte_slot(mem, target.cr3, 0x20000);
    REQUIRE(dirty);
    REQUIRE((dirty->pte & kPteAddrMask) == (0x40ull << 12));
    uint32_t first_end = 0;
    uint32_t second_end = 0;
    auto raw_first = mem.read(kNode + 0x1C, 4);
    auto raw_second = mem.read(kNext + 0x1C, 4);
    REQUIRE(raw_first.size() == 4);
    REQUIRE(raw_second.size() == 4);
    std::memcpy(&first_end, raw_first.data(), 4);
    std::memcpy(&second_end, raw_second.data(), 4);
    REQUIRE(first_end == 0x1F);
    REQUIRE(second_end == 0x310);
}

TEST_CASE("adjacent vad without a node refuses before the image is written", "[integration]") {
    LogSilence quiet;
    auto info = make_info(200);
    info.vad_ranges.push_back({0x10000, 0x1FFFF});
    SimulatedMemory mem(info);
    plant_free_list(mem, 200);
    Target target = mem.find_process("notepad.exe");
    REQUIRE_THROWS_AS(allocate(mem, target, 0x1000, kPageExecuteReadWrite), AllocationError);
    REQUIRE_FALSE(existing_pte_slot(mem, target.cr3, 0x20000).has_value());
    REQUIRE(mem.read_u64(kListHead) == static_cast<uint64_t>(200));
}

TEST_CASE("active pages produce a short pfn claim", "[integration]") {
    LogSilence quiet;
    SimulatedMemory mem(make_info(64));
    mem.set_symbol("MmPfnDatabase", kDbPtr);
    mem.write_u64(kDbPtr, kDb);
    for (int i = 0; i < 64; ++i) mem.set_pfn_type(kFirstPfn + static_cast<uint64_t>(i), "Active");
    Target target = mem.find_process("notepad.exe");
    REQUIRE_THROWS_AS(allocate_physical_pages(mem, 0x1000), PfnError);
}

TEST_CASE("a torn unlink restore aborts the claim", "[integration]") {
    LogSilence quiet;
    class Torn : public SimulatedMemory {
    public:
        using SimulatedMemory::SimulatedMemory;
        bool armed = false;
        int writes = 0;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            if (armed && writes >= 2) throw SessionError("dma glitch");
            ++writes;
            SimulatedMemory::write(address, data, physical, pid);
        }
    } mem(make_info(200));
    plant_free_list(mem, 200);
    mem.armed = true;
    mem.writes = 0;
    REQUIRE_THROWS_AS(allocate_physical_pages(mem, 0x1000), PfnRollbackError);
}

TEST_CASE("stub page past the image is mapped when the image fills the hole", "[integration]") {
    LogSilence quiet;
    auto mem = ready_target();
    Target target = mem.find_process("notepad.exe");
    plant_covering_vad(mem, target.eprocess);
    auto pe = PeImage::parse(minimal_pe());
    auto allocation = allocate(mem, target, 0x3000, kPageExecuteReadWrite);
    REQUIRE(allocation.vad_node != 0);
    pe.size_of_image = static_cast<uint32_t>(allocation.size);
    uint64_t before = allocation.size;
    auto hook = install_hook(mem, target, allocation, pe, "user32.dll", "PeekMessageW",
                             "LaunchHello");
    REQUIRE(allocation.size == before + kPageSize);
    REQUIRE(hook.stub_va >= allocation.va + before);
    REQUIRE(hook.cow_frame != 0);
    auto slot = existing_pte_slot(mem, target.cr3, allocation.va + before);
    REQUIRE(slot);
    REQUIRE(slot->pte & kPteP);
}

TEST_CASE("shared tick export is refused after the image is mapped", "[integration]") {
    LogSilence quiet;
    auto mem = ready_target();
    Target target = mem.find_process("notepad.exe");
    auto pe = PeImage::parse(minimal_pe());
    auto allocation = allocate(mem, target, 0x3000, kPageExecuteReadWrite);
    write_image(mem, target, allocation.va, pe.mapped(allocation.va));
    REQUIRE_THROWS_AS(install_hook(mem, target, allocation, pe, "Kernel32.dll", "GetTickCount",
                                   "LaunchHello"),
                      HookError);
    auto mz = mem.read(allocation.va, 2, false, target.pid);
    REQUIRE(mz.size() == 2);
    REQUIRE(mz[0] == 'M');
}

TEST_CASE("sixty four page allocation maps both ends", "[integration]") {
    LogSilence quiet;
    constexpr int kPages = 64;
    auto mem = ready_target(kPages + kTableSlack + 8);
    Target target = mem.find_process("notepad.exe");
    auto allocation = allocate(mem, target, kPages * kPageSize, kPageExecuteReadWrite);
    REQUIRE(allocation.pages.frames.size() == static_cast<size_t>(kPages));
    REQUIRE(allocation.va == 0x10000);
    auto first = existing_pte_slot(mem, target.cr3, allocation.va);
    auto last = existing_pte_slot(mem, target.cr3, allocation.va + (kPages - 1) * kPageSize);
    REQUIRE(first);
    REQUIRE(last);
    REQUIRE(first->pte & kPteP);
    REQUIRE(last->pte & kPteP);
    REQUIRE((first->pte & kPteAddrMask) == (allocation.pages.frames.front() << 12));
    REQUIRE((last->pte & kPteAddrMask) == (allocation.pages.frames.back() << 12));
}

TEST_CASE("color claim walks the list tail instead of the first free pfn", "[integration]") {
    LogSilence quiet;
    constexpr int kPfns = 40;
    SimulatedMemory mem(make_info(kPfns));
    plant_free_list(mem, kPfns);
    mem.set_symbol("MiState", 0x80000);
    mem.set_symbol("MmNumberOfChannels", 0x88040);
    mem.set_symbol("MiPageSizes", 0x88000);
    mem.set_field_offset("_MI_SYSTEM_INFORMATION", "Hardware", 0x100);
    mem.set_field_offset("_MI_SYSTEM_INFORMATION", "Partitions", 0x200);
    mem.set_field_offset("_MI_HARDWARE_STATE", "PageColors", 0x20);
    mem.set_field_offset("_MI_HARDWARE_STATE", "NumaMemoryRanges", 0x40);
    mem.set_field_offset("_MI_HARDWARE_STATE", "NumaLastRangeIndexInclusive", 0x48);
    mem.set_field_offset("_MI_HARDWARE_STATE", "ChannelMemoryRanges", 0x50);
    mem.set_field_offset("_MI_PARTITION_STATE", "Partition", 0x10);
    mem.set_field_offset("_MI_PARTITION", "Core", 0);
    mem.set_field_offset("_MI_PARTITION_CORE", "NodeInformation", 0x10);
    mem.set_field_offset("_MI_NODE_INFORMATION", "FreePageInfo", 0);
    mem.set_field_offset("_MI_NODE_FREE_PAGE_INFORMATION", "LargePageEntries", 0x40);
    mem.set_type_size("_MI_NODE_INFORMATION", 0x1000);
    mem.set_type_size("_MMPFNLIST", 0x58);
    uint8_t channels = 1;
    mem.write(0x88040, std::span<const uint8_t>(&channels, 1));
    mem.write_u64(0x88000 + 24, 1);
    uint32_t colors = 1;
    mem.write(0x80120 + 12, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&colors), 4));
    mem.write_u64(0x80210, 0x81000);
    mem.write_u64(0x81000, 0x82000);
    mem.write_u64(0x82010, 0x83000);
    // cache 0, zeroed list, 4K. Matches color_list_head's slot.
    const int index = 4 * (2 * (0 + 2 * (10 * 3)));
    mem.write_u64(0x83000 + 0x40 + static_cast<uint64_t>(index) * 8, 0x90000);
    const uint64_t tail = kFirstPfn + static_cast<uint64_t>(kPfns - 1);
    mem.write_u64(0x90000, static_cast<uint64_t>(kPfns));
    mem.write_u64(0x90000 + 0x10, kFirstPfn);
    mem.write_u64(0x90000 + 0x18, tail);

    auto claimed = allocate_physical_pages(mem, kPageSize);
    constexpr int kTaken = 1 + kTableSlack;
    REQUIRE(claimed.frames.size() == 1);
    REQUIRE(static_cast<int>(claimed.table_frames.size()) == kTableSlack);
    REQUIRE(claimed.frames.front() == tail);
    REQUIRE(claimed.table_frames.back() == tail - static_cast<uint64_t>(kTaken - 1));
    REQUIRE(*mem.read_u64(0x90000) == static_cast<uint64_t>(kPfns - kTaken));
    REQUIRE((*mem.read_u64(0x90000 + 0x18) & kPfnMask) == tail - static_cast<uint64_t>(kTaken));
    auto kept = mem.read(kDb + kFirstPfn * kMmpfn + 0x22, 1);
    REQUIRE(kept.size() == 1);
    REQUIRE((kept[0] & 0x07) == kZeroedPageList);
    auto taken = mem.read(kDb + tail * kMmpfn + 0x22, 1);
    REQUIRE(taken.size() == 1);
    REQUIRE((taken[0] & 0x07) == kActiveAndValid);
}

// Same color world as the tail-walk claim. `extra` is added on top of the
// real chain length so Total stays high after the per-page decrements.
static SimulatedMemory color_claim_world(int pfn_count, uint64_t extra) {
    SimulatedMemory mem(make_info(pfn_count));
    plant_free_list(mem, pfn_count);
    mem.set_symbol("MiState", 0x80000);
    mem.set_symbol("MmNumberOfChannels", 0x88040);
    mem.set_symbol("MiPageSizes", 0x88000);
    mem.set_field_offset("_MI_SYSTEM_INFORMATION", "Hardware", 0x100);
    mem.set_field_offset("_MI_SYSTEM_INFORMATION", "Partitions", 0x200);
    mem.set_field_offset("_MI_HARDWARE_STATE", "PageColors", 0x20);
    mem.set_field_offset("_MI_HARDWARE_STATE", "NumaMemoryRanges", 0x40);
    mem.set_field_offset("_MI_HARDWARE_STATE", "NumaLastRangeIndexInclusive", 0x48);
    mem.set_field_offset("_MI_HARDWARE_STATE", "ChannelMemoryRanges", 0x50);
    mem.set_field_offset("_MI_PARTITION_STATE", "Partition", 0x10);
    mem.set_field_offset("_MI_PARTITION", "Core", 0);
    mem.set_field_offset("_MI_PARTITION_CORE", "NodeInformation", 0x10);
    mem.set_field_offset("_MI_NODE_INFORMATION", "FreePageInfo", 0);
    mem.set_field_offset("_MI_NODE_FREE_PAGE_INFORMATION", "LargePageEntries", 0x40);
    mem.set_type_size("_MI_NODE_INFORMATION", 0x1000);
    mem.set_type_size("_MMPFNLIST", 0x58);
    uint8_t channels = 1;
    mem.write(0x88040, std::span<const uint8_t>(&channels, 1));
    mem.write_u64(0x88000 + 24, 1);
    uint32_t colors = 1;
    mem.write(0x80120 + 12, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&colors), 4));
    mem.write_u64(0x80210, 0x81000);
    mem.write_u64(0x81000, 0x82000);
    mem.write_u64(0x82010, 0x83000);
    const int index = 4 * (2 * (0 + 2 * (10 * 3)));
    mem.write_u64(0x83000 + 0x40 + static_cast<uint64_t>(index) * 8, 0x90000);
    const uint64_t tail = kFirstPfn + static_cast<uint64_t>(pfn_count - 1);
    mem.write_u64(0x90000, static_cast<uint64_t>(pfn_count) + extra);
    mem.write_u64(0x90000 + 0x10, kFirstPfn);
    mem.write_u64(0x90000 + 0x18, tail);
    return mem;
}

TEST_CASE("color total above the reachable chain is lowered to that chain", "[integration]") {
    LogSilence quiet;
    constexpr int kPfns = 40;
    constexpr uint64_t kExtra = 9;
    constexpr int kTaken = 1 + kTableSlack;
    auto mem = color_claim_world(kPfns, kExtra);
    auto claimed = allocate_physical_pages(mem, kPageSize);
    REQUIRE(claimed.frames.size() == 1);
    REQUIRE(static_cast<int>(claimed.table_frames.size()) == kTableSlack);
    REQUIRE(*mem.read_u64(0x90000) == static_cast<uint64_t>(kPfns - kTaken));
}

TEST_CASE("a broken color chain is not capped from a stale total", "[integration]") {
    LogSilence quiet;
    constexpr int kPfns = 40;
    constexpr uint64_t kExtra = 9;
    constexpr int kTaken = 1 + kTableSlack;
    auto mem = color_claim_world(kPfns, kExtra);
    // An early page the tail harvest does not splice. The back-walk must
    // refuse this chain instead of publishing the stale total downward.
    mem.write_u64(kDb + (kFirstPfn + 2) * kMmpfn, 0x12345);
    auto claimed = allocate_physical_pages(mem, kPageSize);
    REQUIRE(claimed.frames.size() == 1);
    REQUIRE(*mem.read_u64(0x90000) == static_cast<uint64_t>(kPfns) + kExtra - kTaken);
}

TEST_CASE("four allocations skip frames already marked active", "[stress]") {
    LogSilence quiet;
    // Each claim marks the data page and the unused table slack Active
    // before the next unlink. The planted pool covers these four maps.
    constexpr int kRounds = 4;
    constexpr int kPfns = kRounds * (1 + kTableSlack) + 8;
    SimulatedMemory mem(make_info(kPfns));
    plant_free_list(mem, kPfns);
    Target planted = mem.find_process("notepad.exe");
    plant_covering_vad(mem, planted.eprocess);
    for (int i = 0; i < kRounds; ++i) {
        Target target = planted;
        target.cr3 = 0x200000 + static_cast<uint64_t>(i) * kPageSize;
        mem.write_u64(kCoveringVad + 0xC, 0xF);
        auto allocation = allocate(mem, target, kPageSize, kPageExecuteReadWrite);
        REQUIRE(allocation.pages.frames.size() == 1);
        REQUIRE(allocation.va == 0x10000);
        auto slot = existing_pte_slot(mem, target.cr3, allocation.va);
        REQUIRE(slot);
        REQUIRE(slot->pte & kPteP);
        REQUIRE((slot->pte & kPteAddrMask) == (allocation.pages.frames.front() << 12));
    }
    auto total = mem.read_u64(kListHead);
    REQUIRE(total);
    REQUIRE(*total == static_cast<uint64_t>(kPfns - kRounds * (1 + kTableSlack)));
}

static void plant_named_list(SimulatedMemory& mem, uint64_t head, int list_name, int count) {
    for (int i = 0; i < count; ++i) {
        uint64_t pfn = kFirstPfn + static_cast<uint64_t>(i);
        uint64_t va = kDb + pfn * kMmpfn;
        uint64_t flink = (i + 1 < count) ? pfn + 1 : kPfnTerminator;
        uint64_t blink = (i > 0) ? pfn - 1 : kPfnTerminator;
        mem.write_u64(va, flink);
        mem.write_u64(va + 0x18, blink);
        uint8_t loc = static_cast<uint8_t>(list_name);
        mem.write(va + 0x22, std::span<const uint8_t>(&loc, 1));
    }
    mem.write_u64(head, static_cast<uint64_t>(count));
    mem.write_u64(head + 0x10, kFirstPfn);
    mem.write_u64(head + 0x18, kFirstPfn + static_cast<uint64_t>(count) - 1);
    uint32_t name = static_cast<uint32_t>(list_name);
    mem.write(head + 0x0C, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&name), 4));
}

static SimulatedMemory partition_target(uint64_t part) {
    constexpr int kPfns = 48;
    SimulatedMemory mem(make_info(kPfns));
    mem.set_symbol("MmPfnDatabase", kDbPtr);
    mem.write_u64(kDbPtr, kDb);
    for (const char* n : {"MmZeroedPageListHead", "MmFreePageListHead", "MiZeroedPageListHead",
                          "MiFreePageListHead"}) {
        mem.clear_symbol(n);
    }
    mem.set_symbol("MiSystemPartition", part);
    mem.set_type_size("_MMPFNLIST", 0x58);
    mem.set_type_size("MMPFNLIST", 0x58);
    mem.set_field_offset("_MI_PARTITION", "PageLists", 0xb40);
    return mem;
}

TEST_CASE("page list heads follow the pdb fields", "[integration]") {
    LogSilence quiet;
    constexpr uint64_t kPart = 0xFFFFFA8000010000ull;
    constexpr int kPfns = 48;
    auto mem = partition_target(kPart);
    mem.set_field_offset("_MI_PARTITION_PAGE_LISTS", "ZeroedPageListHead", 0);
    mem.set_field_offset("_MI_PARTITION_PAGE_LISTS", "FreePageListHead", 0x100);
    uint64_t base = kPart + 0xb40;
    mem.write_u64(base + 0x58, 0x1111);
    mem.write_u64(base + 0x80, 0x2222);
    uint32_t zeroed_name = kZeroedPageList;
    mem.write(base + 0x0C, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&zeroed_name), 4));
    mem.write_u64(base + 0x10, kPfnTerminator);
    mem.write_u64(base + 0x18, kPfnTerminator);
    plant_named_list(mem, base + 0x100, kFreePageList, kPfns);

    auto claimed = allocate_physical_pages(mem, 0x1000);
    REQUIRE(claimed.frames.size() == 1);
    REQUIRE(static_cast<int>(claimed.table_frames.size()) == kTableSlack);
    REQUIRE(mem.read_u64(base + 0x58) == 0x1111);
    REQUIRE(mem.read_u64(base + 0x80) == 0x2222);
    auto total = mem.read_u64(base + 0x100);
    REQUIRE(total);
    REQUIRE(*total == static_cast<uint64_t>(kPfns - (1 + kTableSlack)));
}

TEST_CASE("page list heads fall back to the 25h2 pitch", "[integration]") {
    LogSilence quiet;
    constexpr uint64_t kPart = 0xFFFFFA8000010000ull;
    constexpr int kPfns = 48;
    auto mem = partition_target(kPart);
    uint64_t base = kPart + 0xb40;
    mem.write_u64(base + 0x58, 0x1111);
    uint32_t zeroed_name = kZeroedPageList;
    mem.write(base + 0x0C, std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&zeroed_name), 4));
    mem.write_u64(base + 0x10, kPfnTerminator);
    mem.write_u64(base + 0x18, kPfnTerminator);
    plant_named_list(mem, base + 0x80, kFreePageList, kPfns);

    auto claimed = allocate_physical_pages(mem, 0x1000);
    REQUIRE(claimed.frames.size() == 1);
    REQUIRE(mem.read_u64(base + 0x58) == 0x1111);
    auto total = mem.read_u64(base + 0x80);
    REQUIRE(total);
    REQUIRE(*total == static_cast<uint64_t>(kPfns - (1 + kTableSlack)));
}

TEST_CASE("one thousand pfn claims keep the free list linked", "[stress]") {
    LogSilence quiet;
    constexpr int kClaims = 1000;
    constexpr int kPfns = kClaims * (1 + kTableSlack) + 8;
    auto info = make_info(kPfns);
    SimulatedMemory mem(info);
    plant_free_list(mem, kPfns);
    for (int i = 0; i < kClaims; ++i) {
        auto claimed = allocate_physical_pages(mem, 0x1000);
        REQUIRE(claimed.frames.size() == 1);
        REQUIRE(static_cast<int>(claimed.table_frames.size()) == kTableSlack);
    }
    auto total = mem.read_u64(kListHead);
    REQUIRE(total);
    REQUIRE(*total == static_cast<uint64_t>(kPfns - kClaims * (1 + kTableSlack)));
}

TEST_CASE("kernel write falls back when the virtual readback changes") {
    class TornReadback : public Memory {
    public:
        std::unordered_map<uint64_t, uint8_t> bytes;
        int virtual_reads = 0;

        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical, uint32_t) override {
            std::vector<uint8_t> buf(size);
            for (size_t i = 0; i < size; ++i) buf[i] = bytes[address + i];
            if (!physical && address == 0x1000 && !buf.empty()) {
                ++virtual_reads;
                buf[0] ^= 0xFF;
            }
            return buf;
        }

        void write(uint64_t address, std::span<const uint8_t> data, bool, uint32_t) override {
            for (size_t i = 0; i < data.size(); ++i) bytes[address + i] = data[i];
        }

        std::optional<uint64_t> virt2phys(uint64_t va, uint32_t) override {
            if (va == 0x1000) return 0x2000;
            return std::nullopt;
        }
    } mem;

    uint8_t bytes[4] = {1, 2, 3, 4};
    mem.write_kernel(0x1000, std::span<const uint8_t>(bytes, 4));
    REQUIRE(mem.virtual_reads >= 1);
    REQUIRE(mem.bytes[0x2000] == 1);
    REQUIRE(mem.bytes[0x2001] == 2);
    REQUIRE(mem.bytes[0x2002] == 3);
    REQUIRE(mem.bytes[0x2003] == 4);
}

TEST_CASE("a failed map restores the vad end") {
    LogSilence quiet;
    class FailDuringMap : public SimulatedMemory {
    public:
        using SimulatedMemory::SimulatedMemory;
        bool saw_extend = false;
        bool fail_phys = false;

        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            SimulatedMemory::write(address, data, physical, pid);
            if (address == kCoveringVad + 0xC) saw_extend = true;
        }

        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            if (fail_phys && physical) throw SessionError("page table unreadable");
            auto got = SimulatedMemory::read(address, size, physical, pid);
            if (saw_extend) fail_phys = true;
            return got;
        }
    } mem(make_info(200));
    plant_free_list(mem, 200);
    Target target = mem.find_process("notepad.exe");
    plant_covering_vad(mem, target.eprocess);
    REQUIRE_THROWS_AS(allocate(mem, target, 0x1000, kPageExecuteReadWrite), SessionError);
    REQUIRE(mem.fail_phys);
    mem.fail_phys = false;
    auto end = mem.read_u64(kCoveringVad + 0xC);
    REQUIRE(end);
    REQUIRE((*end & 0xFFFFFFFF) == 0xF);
}

TEST_CASE("kernel write throws when the readback misses and there is no pa") {
    class TornUnmapped : public Memory {
    public:
        std::unordered_map<uint64_t, uint8_t> bytes;

        std::vector<uint8_t> read(uint64_t address, size_t size, bool, uint32_t) override {
            std::vector<uint8_t> buf(size);
            for (size_t i = 0; i < size; ++i) buf[i] = bytes[address + i];
            if (address == 0x1000 && !buf.empty()) buf[0] ^= 0xFF;
            return buf;
        }

        void write(uint64_t address, std::span<const uint8_t> data, bool, uint32_t) override {
            for (size_t i = 0; i < data.size(); ++i) bytes[address + i] = data[i];
        }
    } mem;

    uint8_t bytes[4] = {1, 2, 3, 4};
    REQUIRE_THROWS_WITH(mem.write_kernel(0x1000, std::span<const uint8_t>(bytes, 4)),
                        "kernel VA write did not stick and has no physical translation");
}
