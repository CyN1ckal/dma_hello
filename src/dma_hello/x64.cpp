// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/x64.hpp"

#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"

#include <array>
#include <cstring>
#include <unordered_set>

namespace dma_hello {
namespace {

constexpr uint8_t kM = 0x01;
constexpr uint8_t kI8 = 0x02;
constexpr uint8_t kI16 = 0x04;
constexpr uint8_t kI32 = 0x08;
constexpr uint8_t kI64 = 0x10;
constexpr uint8_t kR8 = 0x20;
constexpr uint8_t kR32 = 0x40;
constexpr int32_t kRel32Min = static_cast<int32_t>(0x80000000);
constexpr int32_t kRel32Max = 0x7FFFFFFF;

const std::unordered_set<uint8_t> kPrefix = {
    0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67,
};

std::array<uint8_t, 256> fill_op1() {
    std::array<uint8_t, 256> t{};
    for (uint8_t op : {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13,
                       0x18, 0x19, 0x1A, 0x1B, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
                       0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B, 0x63, 0x69, 0x6B, 0x84,
                       0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0xC0,
                       0xC1, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC,
                       0xDD, 0xDE, 0xDF, 0xF6, 0xF7, 0xFE, 0xFF}) {
        t[op] |= kM;
    }
    t[0x69] |= kI32;
    t[0x6B] |= kI8;
    t[0x80] |= kM | kI8;
    t[0x81] |= kM | kI32;
    t[0x82] |= kM | kI8;
    t[0x83] |= kM | kI8;
    t[0xC0] |= kI8;
    t[0xC1] |= kI8;
    t[0xC2] = kI16;
    t[0xC6] |= kI8;
    t[0xC7] |= kI32;
    t[0xE8] = kR32;
    t[0xE9] = kR32;
    t[0xEB] = kR8;
    t[0xE0] = kR8;
    t[0xE1] = kR8;
    t[0xE2] = kR8;
    t[0xE3] = kR8;
    t[0x68] = kI32;
    t[0x6A] = kI8;
    t[0xA8] = kI8;
    t[0xA9] = kI32;
    t[0xB0] = kI8;
    t[0xB8] = kI64;
    t[0x04] = kI8;
    t[0x0C] = kI8;
    t[0x14] = kI8;
    t[0x1C] = kI8;
    t[0x24] = kI8;
    t[0x2C] = kI8;
    t[0x34] = kI8;
    t[0x3C] = kI8;
    t[0x05] = kI32;
    t[0x0D] = kI32;
    t[0x15] = kI32;
    t[0x1D] = kI32;
    t[0x25] = kI32;
    t[0x2D] = kI32;
    t[0x35] = kI32;
    t[0x3D] = kI32;
    for (int op = 0x70; op < 0x80; ++op) t[op] = kR8;
    t[0xC8] = kI16 | kI8;
    return t;
}

std::array<uint8_t, 256> fill_op2() {
    std::array<uint8_t, 256> t{};
    for (int op = 0x80; op < 0x90; ++op) t[op] = kR32;
    for (int op : {0x00, 0x01, 0x02, 0x03, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
                   0x2D, 0x2E, 0x2F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
                   0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                   0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
                   0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x74, 0x75,
                   0x76, 0x7C, 0x7D, 0x7E, 0x7F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                   0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC,
                   0xAD, 0xAF, 0xB0, 0xB1, 0xB3, 0xB6, 0xB7, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
                   0xC1, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
                   0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                   0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
                   0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}) {
        t[op] |= kM;
    }
    t[0xA4] |= kI8;
    t[0xAC] |= kI8;
    t[0xBA] = kM | kI8;
    t[0x70] = kM | kI8;
    t[0x71] = kM | kI8;
    t[0x72] = kM | kI8;
    t[0x73] = kM | kI8;
    t[0x08] = kM;
    t[0xAE] = kM;
    t[0xC2] = kM | kI8;
    t[0xC4] = kM;
    t[0xC5] = kM;
    t[0xC6] = kM | kI8;
    return t;
}

const std::array<uint8_t, 256> kOp1 = fill_op1();
const std::array<uint8_t, 256> kOp2 = fill_op2();

bool is_simple(uint8_t op) {
    if (op >= 0x50 && op <= 0x5F) return true;
    switch (op) {
    case 0x90:
    case 0xC3:
    case 0xC9:
    case 0xCB:
    case 0xCC:
    case 0xCF:
    case 0x9B:
    case 0x99:
    case 0x98:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F:
    case 0xF5:
    case 0xF8:
    case 0xF9:
    case 0xFC:
    case 0xFD:
    case 0xA4:
    case 0xA5:
    case 0xAA:
    case 0xAB:
    case 0xAC:
    case 0xAD:
    case 0xAE:
    case 0xAF:
    case 0xA6:
    case 0xA7:
    case 0x6C:
    case 0x6D:
    case 0x6E:
    case 0x6F:
    case 0xEC:
    case 0xED:
    case 0xEE:
    case 0xEF:
    case 0x27:
    case 0x2F:
    case 0x37:
    case 0x3F:
        return true;
    default:
        return false;
    }
}

int64_t signed_delta(uint64_t target, uint64_t rip) {
    return static_cast<int64_t>(target - rip);
}

int32_t signed_rel32(uint64_t target, uint64_t rip) {
    int64_t delta = signed_delta(target, rip);
    if (delta < kRel32Min || delta > kRel32Max) {
        throw HookError("RIP-relative displacement does not fit in rel32");
    }
    return static_cast<int32_t>(delta);
}

void mov_rax(std::vector<uint8_t>& out, uint64_t value) {
    out.insert(out.end(), {0x48, 0xB8});
    append_u64(out, value);
}

void mov_rcx(std::vector<uint8_t>& out, uint64_t value) {
    out.insert(out.end(), {0x48, 0xB9});
    append_u64(out, value);
}

void mov_rdx(std::vector<uint8_t>& out, uint64_t value) {
    out.insert(out.end(), {0x48, 0xBA});
    append_u64(out, value);
}

} // namespace

Insn decode_insn(std::span<const uint8_t> code) {
    if (code.empty()) throw HookError("empty buffer for instruction decode");
    int i = 0;
    bool op_size_16 = false;
    bool addr_size_32 = false;
    bool rex_w = false;
    const int n = static_cast<int>(code.size());

    while (i < n && kPrefix.count(code[i])) {
        if (code[i] == 0x66) op_size_16 = true;
        else if (code[i] == 0x67) addr_size_32 = true;
        ++i;
        if (i > 15) throw HookError("instruction prefix overflow");
    }
    if (i < n && (code[i] & 0xF0) == 0x40) {
        rex_w = (code[i] & 0x08) != 0;
        ++i;
    }
    if (i >= n) throw HookError("truncated instruction");

    uint8_t op = code[i++];
    uint8_t flags = 0;
    bool group_f6 = false;
    bool group_f7 = false;
    bool two_byte = false;
    uint8_t op2 = 0;

    if (op == 0x0F) {
        if (i >= n) throw HookError("truncated two-byte opcode");
        two_byte = true;
        op2 = code[i++];
        if (op2 == 0x38 || op2 == 0x3A) {
            if (i >= n) throw HookError("truncated 0F38/0F3A opcode");
            ++i;
            flags = kM;
            if (op2 == 0x3A) flags |= kI8;
        } else {
            flags = kOp2[op2];
        }
    } else if (op >= 0xB0 && op <= 0xB7) {
        flags = kI8;
    } else if (op >= 0xB8 && op <= 0xBF) {
        flags = kI64;
    } else if (is_simple(op)) {
        flags = 0;
        if (op == 0x27 || op == 0x2F || op == 0x37 || op == 0x3F) {
            throw HookError("invalid 64-bit opcode");
        }
    } else if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) {
        i += addr_size_32 ? 4 : 8;
        return Insn{i, std::nullopt, 0, std::nullopt};
    } else if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7 || op == 0xD4 || op == 0xD5) {
        flags = kI8;
    } else if (op == 0xC2 || op == 0xCA) {
        flags = kI16;
    } else {
        flags = kOp1[op];
        group_f6 = op == 0xF6;
        group_f7 = op == 0xF7;
    }

    std::optional<int> rip_disp_at;
    if (flags & kM) {
        if (i >= n) throw HookError("truncated ModRM");
        uint8_t modrm = code[i++];
        int mod = modrm >> 6;
        int rm = modrm & 7;
        if (group_f6 && ((modrm >> 3) & 7) <= 1) flags |= kI8;
        if (group_f7 && ((modrm >> 3) & 7) <= 1) flags |= kI32;
        if (mod != 3 && rm == 4 && !addr_size_32) {
            if (i >= n) throw HookError("truncated SIB");
            uint8_t sib = code[i++];
            int base = sib & 7;
            if (mod == 0 && base == 5) i += 4;
        } else if (mod != 3 && rm == 4 && addr_size_32) {
            if (i >= n) throw HookError("truncated SIB");
            ++i;
        }
        if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
        else if (mod == 0 && rm == 5) {
            rip_disp_at = i;
            i += 4;
        } else if (mod == 0 && addr_size_32 && rm == 6) {
            i += 2;
        }
    }

    std::optional<int> rel_at;
    int rel_size = 0;
    if (flags & kI8) i += 1;
    if (flags & kI16) i += 2;
    if (flags & kI32) i += op_size_16 ? 2 : 4;
    if (flags & kI64) {
        if (rex_w) i += 8;
        else if (op_size_16) i += 2;
        else i += 4;
    }
    if (flags & kR8) {
        rel_at = i;
        rel_size = 1;
        i += 1;
    }
    if (flags & kR32) {
        rel_at = i;
        rel_size = 4;
        i += 4;
    }
    (void)two_byte;
    if (i > n || i > 15) throw HookError("instruction length is out of range");
    if (i == 0) throw HookError("unrecognized opcode");
    return Insn{i, rel_at, rel_size, rip_disp_at};
}

int insn_len(std::span<const uint8_t> code) { return decode_insn(code).length; }

std::vector<uint8_t> steal_bytes(std::span<const uint8_t> code, int minimum) {
    int i = 0;
    while (i < minimum) {
        if (i >= static_cast<int>(code.size())) {
            throw HookError("need more instruction bytes than were supplied");
        }
        i += insn_len(code.subspan(i));
    }
    return {code.begin(), code.begin() + i};
}

std::vector<uint8_t> relocate_stolen(std::span<const uint8_t> code, uint64_t src_va,
                                     uint64_t dst_va, std::vector<FarBranch>* far) {
    std::vector<uint8_t> out(code.begin(), code.end());
    size_t i = 0;
    while (i < out.size()) {
        auto insn = decode_insn(std::span<const uint8_t>(out.data() + i, out.size() - i));
        uint64_t new_rip = dst_va + i + insn.length;
        uint64_t old_rip = src_va + i + insn.length;
        if (insn.rip_disp_at) {
            size_t at = i + *insn.rip_disp_at;
            int32_t old_disp = load_le<int32_t>(out.data() + at);
            uint64_t target = old_rip + static_cast<int64_t>(old_disp);
            int32_t new_disp = signed_rel32(target, new_rip);
            store_le(out.data() + at, new_disp);
        } else if (insn.rel_at) {
            size_t at = i + *insn.rel_at;
            int64_t old_disp = insn.rel_size == 4 ? load_le<int32_t>(out.data() + at)
                                                 : load_le<int8_t>(out.data() + at);
            int64_t orig_off = static_cast<int64_t>(old_rip - src_va) + old_disp;
            if (orig_off >= 0 && orig_off <= static_cast<int64_t>(out.size())) {
                i += insn.length;
                continue;
            }
            uint64_t target = old_rip + old_disp;
            int64_t delta = signed_delta(target, new_rip);
            if (insn.rel_size == 4) {
                if (delta < kRel32Min || delta > kRel32Max) {
                    // The call or jump itself stays. link_trampoline aims it
                    // at an absolute island, so a call still returns to the
                    // next stolen instruction.
                    if (!far) throw HookError("stolen rel32 does not fit after relocate");
                    far->push_back(FarBranch{at, target});
                } else {
                    store_le(out.data() + at, static_cast<int32_t>(delta));
                }
            } else {
                if (delta < -128 || delta > 127) {
                    throw HookError("stolen rel8 does not fit after relocate");
                }
                store_le(out.data() + at, static_cast<int8_t>(delta));
            }
        }
        i += insn.length;
    }
    return out;
}

std::vector<uint8_t> link_trampoline(std::vector<uint8_t> body, const std::vector<FarBranch>& far,
                                     uint64_t trampoline_va, uint64_t resume_va) {
    auto back = encode_jump(trampoline_va + body.size(), resume_va);
    uint64_t island_va = trampoline_va + body.size() + back.size();
    std::vector<uint8_t> islands;
    for (const auto& branch : far) {
        auto island = abs_jump(branch.target);
        uint64_t from = trampoline_va + branch.disp_at + 4;
        store_le(body.data() + branch.disp_at, signed_rel32(island_va, from));
        island_va += island.size();
        islands.insert(islands.end(), island.begin(), island.end());
    }
    body.insert(body.end(), back.begin(), back.end());
    body.insert(body.end(), islands.begin(), islands.end());
    return body;
}

std::vector<uint8_t> abs_jump(uint64_t dst) {
    std::vector<uint8_t> out = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    append_u64(out, dst);
    return out;
}

std::vector<uint8_t> encode_jump(uint64_t src, uint64_t dst) {
    int64_t rel = static_cast<int64_t>(dst - (src + 5));
    if (rel >= kRel32Min && rel <= kRel32Max) {
        std::vector<uint8_t> out = {0xE9};
        append_i32(out, static_cast<int32_t>(rel));
        return out;
    }
    return abs_jump(dst);
}

std::vector<uint8_t> build_oneshot_stub(uint64_t flag_va, uint64_t dll_base,
                                        std::optional<uint64_t> dll_main, uint64_t export_va,
                                        uint64_t trampoline_va) {
    auto jmp_tr = abs_jump(trampoline_va);
    std::vector<uint8_t> head;
    // PeekMessageW's HWND and MSG* live in rcx and rdx. The gate needs both
    // registers, and every later call takes the failure path straight into
    // the stolen prologue. Save the arguments first and restore them on both
    // paths. Expected value 0 in AL, source 1 in CL: lock cmpxchg stores 1
    // only while the flag is still 0.
    head.insert(head.end(), {0x51, 0x52});
    head.insert(head.end(), {0x31, 0xC0});
    mov_rdx(head, flag_va);
    head.insert(head.end(), {0xB1, 0x01});
    head.insert(head.end(), {0xF0, 0x0F, 0xB0, 0x0A});
    head.insert(head.end(), {0x5A, 0x59});
    head.insert(head.end(), {0x0F, 0x85, 0x00, 0x00, 0x00, 0x00});
    size_t je_at = head.size();

    std::vector<uint8_t> body;
    body.insert(body.end(), {0x51, 0x52, 0x41, 0x50, 0x41, 0x51});
    body.insert(body.end(), {0x48, 0x83, 0xEC, 0x28});
    if (dll_main) {
        mov_rcx(body, dll_base);
        mov_rdx(body, 1);
        body.insert(body.end(), {0x4D, 0x31, 0xC0});
        mov_rax(body, *dll_main);
        body.insert(body.end(), {0xFF, 0xD0});
    }
    mov_rax(body, export_va);
    body.insert(body.end(), {0xFF, 0xD0});
    body.insert(body.end(), {0x48, 0x83, 0xC4, 0x28});
    body.insert(body.end(), {0x41, 0x59, 0x41, 0x58, 0x5A, 0x59});
    append_bytes(body, jmp_tr);

    int32_t rel_je = static_cast<int32_t>(body.size());
    store_le(head.data() + je_at - 4, rel_je);

    std::vector<uint8_t> out = std::move(head);
    append_bytes(out, body);
    append_bytes(out, jmp_tr);
    return out;
}

} // namespace dma_hello
