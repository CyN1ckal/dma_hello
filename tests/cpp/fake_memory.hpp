// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/constants.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace dma_hello {
namespace test {

class KernelMemory : public Memory {
public:
    explicit KernelMemory(size_t size = 0x100000) : mem(size) {}

    std::vector<uint8_t> mem;

    std::vector<uint8_t> read(uint64_t address, size_t size, bool = false, uint32_t = 0) override {
        if (address >= mem.size()) return {};
        size_t n = (std::min)(size, mem.size() - static_cast<size_t>(address));
        return {mem.begin() + static_cast<ptrdiff_t>(address),
                mem.begin() + static_cast<ptrdiff_t>(address + n)};
    }

    void write(uint64_t address, std::span<const uint8_t> data, bool = false, uint32_t = 0) override {
        if (address + data.size() > mem.size()) {
            throw SessionError("fake kernel write out of range");
        }
        std::memcpy(mem.data() + address, data.data(), data.size());
    }

    void write_kernel(uint64_t address, std::span<const uint8_t> data) override {
        write(address, data);
    }
};

class FlakyKernel : public KernelMemory {
public:
    explicit FlakyKernel(int fail_on, size_t size = 0x100000) : KernelMemory(size), fail_on(fail_on) {}
    int writes = 0;
    int fail_on = 3;

    void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
               uint32_t pid = 0) override {
        ++writes;
        if (writes == fail_on) throw SessionError("dma glitch");
        KernelMemory::write(address, data, physical, pid);
    }
};

class PhysMemory : public Memory {
public:
    std::unordered_map<uint64_t, std::vector<uint8_t>> pages;
    std::unordered_map<std::string, uint64_t> symbols{{"MmPteBase", kDefaultPteBase}};

    PhysMemory() { write_u64(kDefaultPteBase, kDefaultPteBase); }

    std::vector<uint8_t>& page(uint64_t pa) {
        uint64_t key = pa & ~0xFFFull;
        auto it = pages.find(key);
        if (it == pages.end()) it = pages.emplace(key, std::vector<uint8_t>(kPageSize, 0)).first;
        return it->second;
    }

    std::vector<uint8_t> read(uint64_t address, size_t size, bool = false, uint32_t = 0) override {
        std::vector<uint8_t> buf(size);
        for (size_t i = 0; i < size; ++i) buf[i] = page(address + i)[(address + i) & 0xFFF];
        return buf;
    }

    void write(uint64_t address, std::span<const uint8_t> data, bool = false, uint32_t = 0) override {
        for (size_t i = 0; i < data.size(); ++i) page(address + i)[(address + i) & 0xFFF] = data[i];
    }

    void write_kernel(uint64_t address, std::span<const uint8_t> data) override { write(address, data); }

    std::optional<uint64_t> symbol(const char* name) override {
        auto it = symbols.find(name ? name : "");
        if (it == symbols.end()) return std::nullopt;
        return it->second;
    }

    std::vector<uint64_t> plant_4k(uint64_t cr3, uint64_t va, uint64_t frame,
                                   std::span<const uint8_t> payload,
                                   std::vector<uint64_t> table_pfns) {
        auto idx = [&](int shift) { return static_cast<int>((va >> shift) & 0x1FF); };
        uint64_t pml4 = cr3 & kPteAddrMask;
        auto ensure = [&](uint64_t table_pa, int index) {
            uint64_t slot = table_pa + static_cast<uint64_t>(index) * 8;
            uint64_t entry = read_u64(slot, true).value_or(0);
            if (entry & kPteP) return entry & kPteAddrMask;
            uint64_t pfn = table_pfns.front();
            table_pfns.erase(table_pfns.begin());
            std::vector<uint8_t> zero(kPageSize, 0);
            write(pfn << 12, zero, true);
            write_u64(slot, (pfn << 12) | kPteP | kPteRw | kPteUs | kPteNx, true);
            return pfn << 12;
        };
        uint64_t pdpt = ensure(pml4, idx(39));
        uint64_t pd = ensure(pdpt, idx(30));
        uint64_t pt = ensure(pd, idx(21));
        write(frame << 12, payload, true);
        write_u64(pt + static_cast<uint64_t>(idx(12)) * 8,
                  (frame << 12) | kPteP | kPteRw | kPteUs, true);
        return table_pfns;
    }
};

} // namespace test
} // namespace dma_hello
