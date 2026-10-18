// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace dma_hello {

struct Insn {
    int length = 0;
    std::optional<int> rel_at;
    int rel_size = 0;
    std::optional<int> rip_disp_at;
};

Insn decode_insn(std::span<const uint8_t> code);
int insn_len(std::span<const uint8_t> code);
std::vector<uint8_t> steal_bytes(std::span<const uint8_t> code, int minimum);

// A stolen rel32 whose target is more than 2 GB from the trampoline. The
// displacement is left unchanged until link_trampoline points it at an
// absolute jump island.
struct FarBranch {
    size_t disp_at = 0;
    uint64_t target = 0;
};

std::vector<uint8_t> relocate_stolen(std::span<const uint8_t> code, uint64_t src_va,
                                     uint64_t dst_va, std::vector<FarBranch>* far = nullptr);
// body, then the jump back to `resume_va`, then one absolute jump per far branch.
std::vector<uint8_t> link_trampoline(std::vector<uint8_t> body, const std::vector<FarBranch>& far,
                                     uint64_t trampoline_va, uint64_t resume_va);
std::vector<uint8_t> encode_jump(uint64_t src, uint64_t dst);
std::vector<uint8_t> abs_jump(uint64_t dst);
std::vector<uint8_t> build_oneshot_stub(uint64_t flag_va, uint64_t dll_base,
                                        std::optional<uint64_t> dll_main, uint64_t export_va,
                                        uint64_t trampoline_va);

} // namespace dma_hello
