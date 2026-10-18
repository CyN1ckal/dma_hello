// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/process.hpp"

#include <cstdint>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace dma_hello {

struct VadSpan {
    uint64_t base_va = 0;
    uint64_t size = 0;
    uint64_t node = 0;
    bool adjacent = false;
};

struct VadCandidate {
    uint64_t base_va = 0;
    uint64_t prev_start = 0;
    uint64_t prev_end = 0;
    bool adjacent = false;
};

bool forbidden_range(uint64_t start, uint64_t size);
std::optional<std::tuple<uint64_t, uint64_t, uint64_t>>
prefer_adjacent(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t size);
// Adjacent holes first, then other gaps. A gap that starts on an adjacent hole
// is not repeated, so a dirty or nodeless adjacent hole is not mapped anyway.
std::vector<VadCandidate> vad_candidates(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                        uint64_t size);
// commit is never set. A missing predecessor node yields nullopt.
std::optional<VadSpan> plan_candidate(Memory& mem, const Target& target,
                                     const VadCandidate& candidate, uint64_t size);
std::optional<uint64_t> first_gap(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                  uint64_t size);
// commit writes EndingVpn. A false commit only finds the covering node.
VadSpan choose_and_extend(Memory& mem, const Target& target, const ClaimedPages& pages,
                          bool commit = true);
bool extend_vad_end(Memory& mem, uint64_t node, uint64_t end_vpn);
// The EndingVpn currently stored, including the high byte when the PDB has it.
std::optional<uint64_t> current_vad_end(Memory& mem, uint64_t node);
// The MMVAD that contains va, or 0 when the tree has no such node.
uint64_t vad_covering(Memory& mem, const Target& target, uint64_t va);
// Charge `pages` of private commit. VAD and process commit and
// MmTotalCommittedPages are page counts. The pagefile quota entry is bytes.
// VirtualSize grows only when grow_virtual is set. A field is written only
// when its PDB offset resolves.
void charge_private_commit(Memory& mem, const Target& target, uint64_t vad_node, uint64_t pages,
                           bool grow_virtual);

} // namespace dma_hello
