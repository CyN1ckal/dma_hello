// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/pfn.hpp"

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace dma_hello {

struct NewTable {
    uint64_t pfn = 0;
    uint64_t parent_pfn = 0;
    uint64_t pte_kva = 0;
};

// Why a VA range cannot take new leaves. Clear means every leaf is a zero PTE
// and no large page covers the range.
enum class RangeBlock { Clear, Present, Large, Software, Unreadable };

struct PteSlot {
    uint64_t slot_pa = 0;
    uint64_t pte = 0;
    uint64_t pt_pfn = 0;
};

uint64_t encode_pte(uint64_t frame, uint32_t protection);
// Demand-zero software PTE. MM protection sits in bits 5-9.
uint64_t demand_zero_soft_pte(uint32_t protection);
uint64_t pte_kernel_va(Memory& mem, uint64_t va);
uint64_t table_entry_kernel_va(Memory& mem, uint64_t va, int level);
std::optional<PteSlot> existing_pte_slot(Memory& mem, uint64_t cr3, uint64_t va);
RangeBlock range_block(Memory& mem, uint64_t cr3, uint64_t base_va, int page_count);
uint64_t virt_to_phys(Memory& mem, uint64_t cr3, uint64_t va);
void write_process_va(Memory& mem, uint64_t cr3, uint64_t va, std::span<const uint8_t> data,
                      uint32_t pid);
struct StagedCow {
    uint64_t slot_pa = 0;
    uint64_t pt_pfn = 0;
    uint64_t new_pte = 0;
    uint64_t old_frame = 0;
};

// Copy the source page and build the new leaf. The PTE is not written yet,
// so the caller can publish the new frame Active first.
StagedCow stage_cow_page(Memory& mem, uint64_t cr3, uint64_t va, uint64_t new_frame);
void publish_cow_pte(Memory& mem, const StagedCow& cow);
// published is set once a parent slot or leaf may have been written.
void map_range(Memory& mem, uint64_t cr3, ClaimedPages& pages, uint64_t base_va,
               uint32_t protection, bool* published = nullptr);
void map_one_page(Memory& mem, uint64_t cr3, ClaimedPages& pages, uint64_t va, uint64_t frame,
                  uint32_t protection, bool* published = nullptr);

} // namespace dma_hello
