// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/mm/allocate.hpp"

#include "dma_hello/log.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/mm/vad.hpp"

#include <algorithm>

namespace dma_hello {

const char* block_reason(RangeBlock block) {
    if (block == RangeBlock::Large) return "large page";
    if (block == RangeBlock::Unreadable) return "page table unreadable";
    if (block == RangeBlock::Software) return "software PTE";
    return "present PTE";
}

Allocation allocate(Memory& mem, const Target& target, uint64_t size, uint32_t protection) {
    LOG_INFO("allocating 0x%llx bytes in %s (prot=0x%x)", static_cast<unsigned long long>(size),
             target.name.c_str(), protection);
    if (size == 0 || size > 0x7FFFFFFF000ull) {
        throw AllocationError("allocation does not fit a page count");
    }
    int page_count = static_cast<int>((size + kPageSize - 1) / kPageSize);
    uint64_t bytes = static_cast<uint64_t>(page_count) * kPageSize;
    auto ranges = mem.vad_map(target.pid);
    std::sort(ranges.begin(), ranges.end());
    LOG_INFO("existing VAD entries: %d", static_cast<int>(ranges.size()));
    std::optional<VadSpan> chosen;
    for (const auto& candidate : vad_candidates(ranges, bytes)) {
        auto block = range_block(mem, target.cr3, candidate.base_va, page_count);
        if (block != RangeBlock::Clear) {
            LOG_INFO("skip hole 0x%llx: %s", static_cast<unsigned long long>(candidate.base_va),
                     block_reason(block));
            continue;
        }
        if (!candidate.adjacent) {
            LOG_INFO("skip hole 0x%llx: no adjacent VAD",
                     static_cast<unsigned long long>(candidate.base_va));
            continue;
        }
        auto planned = plan_candidate(mem, target, candidate, bytes);
        if (!planned) {
            LOG_INFO("skip hole 0x%llx: adjacent VAD has no node",
                     static_cast<unsigned long long>(candidate.base_va));
            continue;
        }
        if (planned->adjacent) {
            LOG_INFO("hole after 0x%llx-0x%llx -> 0x%llx",
                     static_cast<unsigned long long>(candidate.prev_start),
                     static_cast<unsigned long long>(candidate.prev_end),
                     static_cast<unsigned long long>(planned->base_va));
        }
        chosen = planned;
        break;
    }
    if (!chosen) {
        throw AllocationError("no VAD hole with clear page tables");
    }
    // Pages are claimed only after every leaf in the chosen range is an empty PTE.
    auto pages = allocate_physical_pages(mem, size);
    VadSpan vad = *chosen;
    try {
        std::optional<uint64_t> old_end;
        if (vad.node) {
            old_end = current_vad_end(mem, vad.node);
            uint64_t end_vpn = (vad.base_va >> 12) + (vad.size / kPageSize) - 1;
            if (!old_end || !extend_vad_end(mem, vad.node, end_vpn)) {
                throw AllocationError("adjacent VAD could not be extended");
            }
            LOG_INFO("extended MMVAD 0x%llx EndingVpn -> 0x%llx",
                     static_cast<unsigned long long>(vad.node),
                     static_cast<unsigned long long>(end_vpn));
        }
        bool published = false;
        try {
            map_range(mem, target.cr3, pages, vad.base_va, protection, &published);
            LOG_INFO("mapped 0x%llx-0x%llx", static_cast<unsigned long long>(vad.base_va),
                     static_cast<unsigned long long>(vad.base_va + vad.size));
            charge_private_commit(mem, target, vad.node, static_cast<uint64_t>(page_count), true);
        } catch (...) {
            // Shrink only when no parent slot or leaf was published.
            if (!published && old_end) {
                try {
                    extend_vad_end(mem, vad.node, *old_end);
                } catch (const std::exception& e) {
                    LOG_ERROR("could not restore EndingVpn on 0x%llx: %s",
                              static_cast<unsigned long long>(vad.node), e.what());
                }
            }
            throw;
        }
    } catch (...) {
        retain_claim(pages);
        throw;
    }
    Allocation a;
    a.va = vad.base_va;
    a.size = vad.size;
    a.pages = std::move(pages);
    a.vad_node = vad.node;
    a.adjacent = vad.adjacent;
    return a;
}

} // namespace dma_hello
