// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/hook.hpp"

#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/mm/vad.hpp"
#include "dma_hello/x64.hpp"

#include <algorithm>
#include <optional>

namespace dma_hello {

constexpr int kAbsJmpLen = 14;
constexpr int kRelJmpLen = 5;
// Padding scan around the hooked export. user32's int3 caves sit well inside this.
constexpr uint64_t kCaveWindow = 0x200000;

// gameoverlayrenderer64 copies one instruction and jumps back to it. On
// PeekMessageW that resume is +5. A 14-byte absolute jump leaves +5 inside
// its address immediate, and the fault is `add byte ptr [rax], dl` there.
std::optional<uint64_t> find_cc_cave(Memory& mem, uint32_t pid, uint64_t hook, int need) {
    uint64_t span_lo = hook > kCaveWindow ? hook - kCaveWindow : 0;
    uint64_t span_hi = hook + kCaveWindow;
    for (auto [start, end] : mem.vad_map(pid)) {
        if (hook < start || hook > end) continue;
        if (start > span_lo) span_lo = start;
        if (end < span_hi) span_hi = end;
        break;
    }
    std::optional<uint64_t> best;
    uint64_t best_dist = ~0ull;
    uint64_t page = span_lo & ~kPageMask;
    for (; page <= span_hi; page += kPageSize) {
        std::vector<uint8_t> bytes;
        try {
            bytes = mem.read(page, static_cast<size_t>(kPageSize), false, pid);
        } catch (const DmaError&) {
            continue;
        }
        if (bytes.size() < kPageSize) continue;
        int run = 0;
        for (int i = 0; i < static_cast<int>(kPageSize); ++i) {
            if (bytes[i] != 0xCC) {
                run = 0;
                continue;
            }
            ++run;
            if (run < need) continue;
            uint64_t cave = page + static_cast<uint64_t>(i + 1 - need);
            if (cave < hook + 32 && cave + static_cast<uint64_t>(need) > hook) continue;
            if (encode_jump(hook, cave).size() != static_cast<size_t>(kRelJmpLen)) continue;
            uint64_t dist = cave > hook ? cave - hook : hook - cave;
            if (dist < best_dist) {
                best = cave;
                best_dist = dist;
            }
        }
        if (page > ~uint64_t{0} - kPageSize) break;
    }
    return best;
}

std::optional<uint64_t> direct_target(uint64_t addr, std::span<const uint8_t> bytes) {
    if (bytes.size() >= static_cast<size_t>(kAbsJmpLen) && bytes[0] == 0xFF && bytes[1] == 0x25 &&
        bytes[2] == 0 && bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0) {
        return load_le<uint64_t>(bytes.data() + 6);
    }
    if (bytes.size() >= static_cast<size_t>(kRelJmpLen) && bytes[0] == 0xE9) {
        return addr + kRelJmpLen + static_cast<int64_t>(load_le<int32_t>(bytes.data() + 1));
    }
    return std::nullopt;
}

bool our_stub(std::span<const uint8_t> bytes) {
    return bytes.size() >= 4 && bytes[0] == 0x51 && bytes[1] == 0x52 && bytes[2] == 0x31 &&
           bytes[3] == 0xC0;
}

// Follow an entry jump and one absolute island. Only the oneshot gate counts
// as our hook. gameoverlayrenderer64 uses the same E9-to-FF-25 shape and must
// stay in the chain.
bool reaches_our_stub(Memory& mem, uint32_t pid, uint64_t addr, std::span<const uint8_t> first) {
    uint64_t cur = addr;
    std::vector<uint8_t> owned;
    std::span<const uint8_t> bytes = first;
    for (int i = 0; i < 3; ++i) {
        if (our_stub(bytes)) return true;
        auto next = direct_target(cur, bytes);
        if (!next || *next == cur) return false;
        cur = *next;
        try {
            owned = mem.read(cur, 16, false, pid);
        } catch (const DmaError&) {
            return false;
        }
        bytes = owned;
    }
    return false;
}

static std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

Hook install_hook(Memory& mem, const Target& target, Allocation& allocation, const PeImage& pe,
                  const std::string& module, const std::string& function,
                  const std::string& export_name) {
    auto mod_l = lower_copy(module);
    auto fn_l = lower_copy(function);
    if ((mod_l == "kernel32.dll" || mod_l == "kernelbase.dll") &&
        (fn_l == "gettickcount" || fn_l == "gettickcount64")) {
        throw HookError(module + "!" + function + " is a shared image; patching it hangs the machine");
    }

    uint64_t hook_addr = mem.export_addr(target.pid, mod_l, fn_l);
    LOG_INFO("found %s!%s at 0x%llx", module.c_str(), function.c_str(),
             static_cast<unsigned long long>(hook_addr));

    auto original = mem.read(hook_addr, 32, false, target.pid);
    if (original.size() < kAbsJmpLen) throw HookError("could not read function prologue");
    if (reaches_our_stub(mem, target.pid, hook_addr, original)) {
        throw HookError(function + " is already hooked; refusing a second COW");
    }
    if (auto prior = direct_target(hook_addr, original)) {
        LOG_INFO("chaining the existing detour of %s to 0x%llx", function.c_str(),
                 static_cast<unsigned long long>(*prior));
    }
    // Stop at the first instruction when a 5-byte jump fits inside it, so a
    // detour that resumes at +5 still executes the original second instruction.
    int first_len = 0;
    try {
        first_len = insn_len(std::span<const uint8_t>(original.data(), original.size()));
    } catch (const HookError&) {
        first_len = 0;
    }
    bool one_insn = first_len >= kRelJmpLen;
    auto stolen = steal_bytes(original, one_insn ? first_len : kAbsJmpLen);
    LOG_INFO("stealing %d bytes of %s", static_cast<int>(stolen.size()), function.c_str());

    uint64_t dll_base = allocation.va;
    uint64_t export_va = pe.export_va(dll_base, export_name);
    auto dll_main = pe.entry_va(dll_base);

    uint64_t code_page = allocation.va + allocation.size - kPageSize;
    if (code_page < allocation.va + pe.size_of_image) {
        if (allocation.spare_frames().size() < 2) {
            throw HookError("stub page overlaps the mapped PE image and no spare frame is left");
        }
        uint64_t ext = allocation.va + allocation.size;
        for (auto [start, end] : mem.vad_map(target.pid)) {
            if (start <= ext + kPageSize - 1 && end >= ext) {
                throw HookError("stub page overlaps the mapped PE image and the next VA is occupied");
            }
        }
        if (!allocation.vad_node) {
            throw HookError("stub page would sit outside a VAD");
        }
        auto old_end = current_vad_end(mem, allocation.vad_node);
        uint64_t end_vpn = ext >> 12;
        if (!old_end || !extend_vad_end(mem, allocation.vad_node, end_vpn)) {
            throw HookError("stub page needs the covering VAD to grow before it is mapped");
        }
        uint64_t frame = allocation.spare_frames().front();
        allocation.spare_frames().erase(allocation.spare_frames().begin());
        bool published = false;
        try {
            map_one_page(mem, target.cr3, allocation.pages, ext, frame, kPageExecuteReadWrite,
                         &published);
            charge_private_commit(mem, target, allocation.vad_node, 1, true);
        } catch (...) {
            if (!published) {
                allocation.spare_frames().insert(allocation.spare_frames().begin(), frame);
                try {
                    extend_vad_end(mem, allocation.vad_node, *old_end);
                } catch (const std::exception& e) {
                    LOG_ERROR("could not restore EndingVpn on 0x%llx: %s",
                              static_cast<unsigned long long>(allocation.vad_node), e.what());
                }
            } else {
                retain_active_frames({frame});
            }
            throw;
        }
        allocation.size += kPageSize;
        code_page = ext;
        LOG_INFO("stub page moved to 0x%llx past the PE image",
                 static_cast<unsigned long long>(code_page));
    }
    uint64_t flag_va = code_page;
    uint64_t stub_va = code_page + 0x10;
    auto stub = build_oneshot_stub(flag_va, dll_base, dll_main, export_va, 0);
    uint64_t trampoline_va = stub_va + stub.size() + 16;
    trampoline_va = (trampoline_va + 15) & ~15ull;
    stub = build_oneshot_stub(flag_va, dll_base, dll_main, export_va, trampoline_va);
    if (code_page < allocation.va + pe.size_of_image) {
        throw HookError("stub page overlaps the mapped PE image");
    }
    std::vector<FarBranch> far;
    auto relocated = relocate_stolen(stolen, hook_addr, trampoline_va, &far);
    auto trampoline = link_trampoline(std::move(relocated), far, trampoline_va,
                                      hook_addr + stolen.size());
    if (trampoline_va + trampoline.size() > code_page + kPageSize) {
        throw HookError("stub and trampoline do not fit in the reserved page");
    }

    uint8_t zeros[8]{};
    write_process_va(mem, target.cr3, flag_va, std::span<const uint8_t>(zeros, 8), target.pid);
    write_process_va(mem, target.cr3, stub_va, stub, target.pid);
    write_process_va(mem, target.cr3, trampoline_va, trampoline, target.pid);
    LOG_INFO("stub 0x%llx trampoline 0x%llx export 0x%llx",
             static_cast<unsigned long long>(stub_va),
             static_cast<unsigned long long>(trampoline_va),
             static_cast<unsigned long long>(export_va));

    uint64_t detour = stub_va;
    std::optional<uint64_t> cave;
    std::vector<uint8_t> patched;
    if (one_insn && encode_jump(hook_addr, stub_va).size() == static_cast<size_t>(kRelJmpLen)) {
        patched = encode_jump(hook_addr, stub_va);
    } else if (one_insn) {
        cave = find_cc_cave(mem, target.pid, hook_addr, kAbsJmpLen);
        if (!cave) {
            throw HookError("no int3 padding within rel32 of the hook; refusing a 14-byte patch");
        }
        detour = *cave;
        patched = encode_jump(hook_addr, detour);
        if (patched.size() != static_cast<size_t>(kRelJmpLen)) {
            throw HookError("code cave is outside rel32 of the hook");
        }
    } else {
        patched = abs_jump(stub_va);
    }
    if (patched.size() > stolen.size()) {
        throw HookError("jump is longer than the stolen prologue");
    }
    patched.resize(stolen.size(), 0x90);
    if ((hook_addr & kPageMask) + patched.size() > kPageSize) {
        throw HookError("hook straddles a page boundary; only one page is COWed");
    }

    uint64_t hook_page = hook_addr & ~kPageMask;
    int cows = 1;
    if (cave && (*cave & ~kPageMask) != hook_page) ++cows;
    if (static_cast<int>(allocation.spare_frames().size()) < cows) {
        throw HookError("no spare PFN for COW; refusing to patch a shared image");
    }

    std::vector<uint64_t> taken;
    auto owned = [&](uint64_t pfn) {
        for (uint64_t frame : taken) {
            if (frame == pfn) return true;
        }
        for (uint64_t frame : allocation.pages.frames) {
            if (frame == pfn) return true;
        }
        for (uint64_t frame : allocation.pages.table_frames) {
            if (frame == pfn) return true;
        }
        for (uint64_t frame : allocation.spare_frames()) {
            if (frame == pfn) return true;
        }
        return false;
    };
    auto cow_page = [&](uint64_t page_va) {
        uint64_t frame = allocation.spare_frames().front();
        allocation.spare_frames().erase(allocation.spare_frames().begin());
        auto staged = stage_cow_page(mem, target.cr3, page_va, frame);
        if (owned(staged.old_frame)) {
            throw HookError("refusing to COW a frame this run already owns");
        }
        taken.push_back(frame);
        mark_pfn_active(mem, allocation.pages, frame, pte_kernel_va(mem, page_va), staged.pt_pfn, 0,
                        demand_zero_soft_pte(kPageExecuteReadWrite));
        publish_cow_pte(mem, staged);
        charge_private_commit(mem, target, vad_covering(mem, target, page_va), 1, false);
        LOG_INFO("COW 0x%llx -> pfn 0x%llx (this process only)",
                 static_cast<unsigned long long>(page_va), static_cast<unsigned long long>(frame));
        return frame;
    };

    uint64_t cow_frame = cow_page(hook_page);
    if (cave) {
        uint64_t cave_page = *cave & ~kPageMask;
        uint64_t cave_frame = cave_page == hook_page ? cow_frame : cow_page(cave_page);
        uint64_t cave_pa = (cave_frame << 12) | (*cave & kPageMask);
        mem.write(cave_pa, abs_jump(stub_va), true);
        LOG_INFO("cave 0x%llx -> stub 0x%llx", static_cast<unsigned long long>(*cave),
                 static_cast<unsigned long long>(stub_va));
    }
    uint64_t hook_pa = (cow_frame << 12) | (hook_addr & kPageMask);
    mem.write(hook_pa, patched, true);
    LOG_INFO("hooked %s at 0x%llx (PA 0x%llx) -> 0x%llx", function.c_str(),
             static_cast<unsigned long long>(hook_addr), static_cast<unsigned long long>(hook_pa),
             static_cast<unsigned long long>(detour));

    Hook h;
    h.function = function;
    h.address = hook_addr;
    h.stolen = static_cast<int>(stolen.size());
    h.stub_va = stub_va;
    h.trampoline_va = trampoline_va;
    h.cow_frame = cow_frame;
    h.hook_pa = hook_pa;
    return h;
}

} // namespace dma_hello
