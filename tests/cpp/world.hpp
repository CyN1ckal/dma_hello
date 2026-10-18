// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/bytes.hpp"
#include "dma_hello/log.hpp"
#include "dma_hello/mm/constants.hpp"
#include "simulated_memory.hpp"
#include "test_target_process.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace dma_hello {
namespace test {

inline constexpr uint64_t kDb = 0xFFFFF80000000000ull;
inline constexpr uint64_t kDbPtr = 0xFFFFF78000001000ull;
inline constexpr uint64_t kListHead = 0xFFFFFA8000002000ull;
inline constexpr uint64_t kFirstPfn = 0x100;
inline constexpr uint64_t kCr3 = 0x8000;
inline constexpr uint64_t kHookVa = 0x7FF812345678ull;
inline constexpr uint64_t kHookFrame = 0x50;
inline constexpr int kMmpfn = 0x30;

inline std::vector<uint8_t> minimal_pe() {
    std::vector<uint8_t> buf(0x600, 0);
    buf[0] = 'M';
    buf[1] = 'Z';
    store_le(buf.data() + 0x3C, uint32_t{0x80});
    buf[0x80] = 'P';
    buf[0x81] = 'E';
    store_le(buf.data() + 0x84, uint16_t{0x8664});
    store_le(buf.data() + 0x86, uint16_t{1});
    store_le(buf.data() + 0x94, uint16_t{0xF0});
    store_le(buf.data() + 0x96, uint16_t{0x22});
    uint32_t opt = 0x84 + 20;
    store_le(buf.data() + opt, uint16_t{0x20B});
    store_le(buf.data() + opt + 16, uint32_t{0x1000});
    store_le(buf.data() + opt + 24, uint64_t{0x140000000});
    store_le(buf.data() + opt + 56, uint32_t{0x2000});
    store_le(buf.data() + opt + 60, uint32_t{0x400});
    store_le(buf.data() + opt + 108, uint32_t{16});
    uint32_t dd = opt + 112;
    store_le(buf.data() + dd + 0, uint32_t{0x1080});
    store_le(buf.data() + dd + 4, uint32_t{0x80});
    store_le(buf.data() + dd + 8, uint32_t{0x1100});
    store_le(buf.data() + dd + 12, uint32_t{0x40});
    store_le(buf.data() + dd + 40, uint32_t{0x1180});
    store_le(buf.data() + dd + 44, uint32_t{0x0C});
    uint32_t sec = opt + 0xF0;
    std::memcpy(buf.data() + sec, ".text", 5);
    store_le(buf.data() + sec + 8, uint32_t{0x200});
    store_le(buf.data() + sec + 12, uint32_t{0x1000});
    store_le(buf.data() + sec + 16, uint32_t{0x200});
    store_le(buf.data() + sec + 20, uint32_t{0x400});
    uint32_t text_off = 0x400;
    store_le(buf.data() + text_off, uint64_t{0x140000000});
    uint32_t ed = text_off + 0x80;
    store_le(buf.data() + ed + 20, uint32_t{1});
    store_le(buf.data() + ed + 24, uint32_t{1});
    uint32_t funcs_rva = 0x1080 + 40;
    uint32_t names_rva = funcs_rva + 4;
    uint32_t ords_rva = names_rva + 4;
    uint32_t name_rva = ords_rva + 2;
    store_le(buf.data() + ed + 28, funcs_rva);
    store_le(buf.data() + ed + 32, names_rva);
    store_le(buf.data() + ed + 36, ords_rva);
    store_le(buf.data() + text_off + (funcs_rva - 0x1000), uint32_t{0x1008});
    store_le(buf.data() + text_off + (names_rva - 0x1000), name_rva);
    store_le(buf.data() + text_off + (ords_rva - 0x1000), uint16_t{0});
    const char* export_name = "LaunchHello";
    uint32_t name_off = text_off + (name_rva - 0x1000);
    std::memcpy(buf.data() + name_off, export_name, 12);
    uint32_t rel = text_off + 0x180;
    store_le(buf.data() + rel, uint32_t{0x1000});
    store_le(buf.data() + rel + 4, uint32_t{12});
    store_le(buf.data() + rel + 8, uint16_t{(10 << 12) | 0});
    return buf;
}

inline TargetProcessInfo make_info(int pfn_count, uint32_t pid = 0x1234, uint64_t cr3 = kCr3,
                                   std::string name = "notepad.exe") {
    return TargetProcessBuilder{}
        .set_name(std::move(name))
        .set_pid(pid)
        .set_cr3(cr3)
        .add_phys_range(kFirstPfn << 12, static_cast<uint64_t>(pfn_count) * kPageSize)
        .build();
}

inline void plant_free_list(SimulatedMemory& mem, int pfn_count) {
    mem.set_symbol("MmPfnDatabase", kDbPtr);
    mem.write_u64(kDbPtr, kDb);
    for (int i = 0; i < pfn_count; ++i) {
        uint64_t pfn = kFirstPfn + static_cast<uint64_t>(i);
        uint64_t va = kDb + pfn * kMmpfn;
        uint64_t flink = (i + 1 < pfn_count) ? pfn + 1 : kPfnTerminator;
        uint64_t blink = (i > 0) ? pfn - 1 : kPfnTerminator;
        mem.write_u64(va, flink);
        mem.write_u64(va + 0x18, blink);
        uint8_t loc = static_cast<uint8_t>(kZeroedPageList);
        mem.write(va + 0x22, std::span<const uint8_t>(&loc, 1));
    }
    mem.write_u64(kListHead, static_cast<uint64_t>(pfn_count));
    mem.write_u64(kListHead + 0x10, kFirstPfn);
    mem.write_u64(kListHead + 0x18, kFirstPfn + static_cast<uint64_t>(pfn_count) - 1);
}

inline void plant_hook_page(Memory& mem, uint64_t cr3 = kCr3) {
    std::vector<uint8_t> nops(kPageSize, 0x90);
    std::vector<uint64_t> tables = {0x10, 0x11, 0x12};
    auto idx = [](uint64_t va, int shift) { return static_cast<int>((va >> shift) & 0x1FF); };
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
    uint64_t pdpt = ensure(pml4, idx(kHookVa, 39));
    uint64_t pd = ensure(pdpt, idx(kHookVa, 30));
    uint64_t pt = ensure(pd, idx(kHookVa, 21));
    mem.write(kHookFrame << 12, nops, true);
    mem.write_u64(pt + static_cast<uint64_t>(idx(kHookVa, 12)) * 8,
                  (kHookFrame << 12) | kPteP | kPteRw | kPteUs, true);
}

inline constexpr uint64_t kCoveringVad = 0xFFFFF78000004000ull;

// One page ending at 0xFFFF, so the next hole is 0x10000 and it has a node.
inline void plant_covering_vad(SimulatedMemory& mem, uint64_t eprocess) {
    mem.add_vad_range(0x0, 0xFFFF);
    mem.write_u64(eprocess + 0x38, kCoveringVad);
    mem.write_u64(kCoveringVad + 0x8, 0);
    mem.write_u64(kCoveringVad + 0xC, 0xF);
}

inline SimulatedMemory ready_target(int pfn_count = 200) {
    SimulatedMemory mem(make_info(pfn_count));
    plant_free_list(mem, pfn_count);
    plant_hook_page(mem);
    plant_covering_vad(mem, mem.find_process("notepad.exe").eprocess);
    return mem;
}

inline bool list_pfn_or_end(uint64_t value, int pfn_count) {
    if (value == kPfnTerminator) return true;
    return value >= kFirstPfn && value < kFirstPfn + static_cast<uint64_t>(pfn_count);
}

struct LogSilence {
    LogSilence() { setup_log(0, ""); }
    ~LogSilence() { setup_log(3, ""); }
};

} // namespace test
} // namespace dma_hello
