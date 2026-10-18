// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/constants.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dma_hello {

struct MmpfnLayout {
    int size = 0x30;
    int u1 = 0;
    int pte_address = 8;
    int u2 = 0x18;
    int u3 = 0x20;
    int u4 = 0x28;
    std::optional<int> original_pte = 0x10;
};

struct MmpfnListLayout {
    int size = 0x28;
    int total = 0;
    int flink = 0x10;
    int blink = 0x18;
};

// Per-color free/zero lists. Enabled only when the kernel PDB supplies the
// MiState fields. A null account keeps the aggregate-list unlink. When the
// account is enabled, only the current color-list tail is removed, and that
// list's Total is dropped before any Flink or Blink store.
struct ColorAccount {
    bool enabled = false;
    uint64_t colors_va = 0;
    uint64_t ranges_va = 0;
    uint64_t last_va = 0;
    uint64_t partition_slot = 0;
    int node_info_off = 0;
    int node_size = 0;
    int entries_off = 0;
    int list_stride = 0;
    uint32_t page_colors = 0;
    uint8_t channels = 1;
    int decrements = 0;
    int aggregate_skips = 0;
    int refuse_color = 0;
    int refuse_empty = 0;
    int refuse_edge = 0;
    int refuse_neighbor = 0;
    int refuse_stale = 0;
    int refuse_batch = 0;
};

struct ClaimedPages {
    int page_count = 0;
    std::vector<uint64_t> frames;
    std::vector<uint64_t> table_frames;
    uint64_t pfn_database = 0;
    MmpfnLayout layout{};
    std::unordered_map<int, uint64_t> list_heads;
    MmpfnListLayout list_layout{};
    std::vector<uint64_t> spare;
};

ClaimedPages allocate_physical_pages(Memory& mem, uint64_t size);
// Already-Active frames stay off the free list. The record lives until exit.
void retain_active_frames(std::vector<uint64_t> frames);
void retain_claim(const ClaimedPages& pages);
// used_entries is the page-table view of u1. Data pages pass 0.
// A new page table keeps ReferenceCount at 1. ShareCount starts at
// used_entries + 1 (the parent residency plus one per child already
// published). The caller adds one more share per later child. An
// operating-system table gains that same per-child share and keeps the
// reference count it already had. The state byte is published Active and
// cached, with Modified clear, before u1 is replaced.
// original_pte is the demand-zero software PTE (0 leaves the field zero).
void mark_pfn_active(Memory& mem, ClaimedPages& pages, uint64_t frame, uint64_t pte_kva,
                     uint64_t pte_frame, int used_entries = 0, uint64_t original_pte = 0,
                     bool table_page = false);

bool on_free_list(int loc);
// Replace the low kPfnBits of qword and keep the node and flag bits above them.
uint64_t set_low_pfn(uint64_t qword, uint64_t pfn);
ColorAccount color_account(Memory& mem);
bool unlink_one(Memory& mem, uint64_t db, const MmpfnLayout& layout, const MmpfnListLayout& lists,
                uint64_t pfn, const std::unordered_map<int, uint64_t>& list_heads, int list_idx,
                ColorAccount* color = nullptr);

} // namespace dma_hello
