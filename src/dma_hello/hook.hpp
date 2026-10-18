// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/pe.hpp"

#include <cstdint>
#include <string>

namespace dma_hello {

struct Allocation {
    uint64_t va = 0;
    uint64_t size = 0;
    ClaimedPages pages;
    uint64_t vad_node = 0;
    bool adjacent = false;

    std::vector<uint64_t>& spare_frames() { return pages.spare; }
};

struct Hook {
    std::string function;
    uint64_t address = 0;
    int stolen = 0;
    uint64_t stub_va = 0;
    uint64_t trampoline_va = 0;
    uint64_t cow_frame = 0;
    uint64_t hook_pa = 0;
};

Hook install_hook(Memory& mem, const Target& target, Allocation& allocation, const PeImage& pe,
                  const std::string& module, const std::string& function,
                  const std::string& export_name);

} // namespace dma_hello
