// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/x64.hpp"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <vector>

using namespace dma_hello;

TEST_CASE("instruction lengths") {
    auto check = [](const char* hex, int n) {
        auto b = hex_bytes(hex);
        REQUIRE(insn_len(b) == n);
    };
    check("48 83 EC 28", 4);
    check("48 89 5C 24 08", 5);
    check("4C 8B DC", 3);
    check("40 53", 2);
    check("55", 1);
    check("C3", 1);
    check("90", 1);
    check("48 8B C4", 3);
    check("48 81 EC 88 00 00 00", 7);
    check("48 8B 05 00 00 00 00", 7);
    check("FF 25 00 00 00 00", 6);
    check("E9 00 00 00 00", 5);
    check("EB 00", 2);
    check("48 B8 78 56 34 12 00 00 00 00", 10);
    check("B8 01 00 00 00", 5);
    check("33 C0", 2);
    check("45 33 C9", 3);
    check("4D 31 C0", 3);
    check("FF D0", 2);
    check("C6 00 01", 3);
    check("80 38 01", 3);
    check("0F 84 00 00 00 00", 6);
    check("F3 0F 1E FA", 4);
}

TEST_CASE("steal complete instructions") {
    auto code = hex_bytes("4C 8B DC 48 81 EC 88 00 00 00 48 8B 05 11 22 33 44");
    auto stolen = steal_bytes(code, 14);
    REQUIRE(stolen.size() >= 14);
    int n = 0;
    while (n < static_cast<int>(stolen.size())) n += insn_len(std::span(stolen).subspan(n));
    REQUIRE(n == static_cast<int>(stolen.size()));
}

TEST_CASE("jumps") {
    auto rel = encode_jump(0x1000, 0x1010);
    REQUIRE(rel[0] == 0xE9);
    REQUIRE(load_le<int32_t>(rel.data() + 1) == 0xB);

    auto absj = encode_jump(0x7FF000000000ull, 0x100000000ull);
    REQUIRE(absj.size() == 14);
    REQUIRE(absj[0] == 0xFF);
    REQUIRE(absj[1] == 0x25);

    uint64_t src = 0x1000;
    uint64_t dst = src + 5 + 0x7FFFFFFF;
    auto maxrel = encode_jump(src, dst);
    REQUIRE(maxrel[0] == 0xE9);
    REQUIRE(load_le<int32_t>(maxrel.data() + 1) == 0x7FFFFFFF);

    dst = src + 5 + 0x80000000ull;
    auto over = encode_jump(src, dst);
    REQUIRE(over == abs_jump(dst));
}

TEST_CASE("relocate rip-relative") {
    uint64_t src = 0x7FF81000, dst = 0x7FF01000;
    int32_t disp = 0x44332211;
    std::vector<uint8_t> code = {0x48, 0x8B, 0x05};
    append_i32(code, disp);
    uint64_t target = src + 7 + disp;
    auto out = relocate_stolen(code, src, dst);
    int32_t new_disp = load_le<int32_t>(out.data() + 3);
    REQUIRE(dst + 7 + new_disp == target);
}

TEST_CASE("relocate rip-relative jmp moffs") {
    uint64_t src = 0x7FF81000, dst = 0x7FF01000;
    int32_t disp = 0x10;
    std::vector<uint8_t> code = {0xFF, 0x25};
    append_i32(code, disp);
    uint64_t target = src + 6 + disp;
    auto out = relocate_stolen(code, src, dst);
    int32_t new_disp = load_le<int32_t>(out.data() + 2);
    REQUIRE(dst + 6 + new_disp == target);
}

TEST_CASE("leave rel8 inside stolen including end") {
    auto code = hex_bytes("75 02 90 90");
    REQUIRE(relocate_stolen(code, 0x1000, 0x8000) == code);
    auto next = hex_bytes("75 00 90 90");
    REQUIRE(relocate_stolen(next, 0x1000, 0x8000) == next);
}

TEST_CASE("steal then relocate rip") {
    uint64_t src = 0x7FF81000, dst = 0x7FF01000;
    auto code = hex_bytes("48 89 5C 24 08 48 8B 05 11 22 33 44 90 90");
    auto stolen = steal_bytes(code, 14);
    REQUIRE(stolen.size() == 14);
    auto out = relocate_stolen(stolen, src, dst);
    REQUIRE(std::vector(out.begin(), out.begin() + 5) ==
            std::vector(stolen.begin(), stolen.begin() + 5));
    int32_t old_disp = load_le<int32_t>(stolen.data() + 8);
    int32_t new_disp = load_le<int32_t>(out.data() + 8);
    REQUIRE(src + 5 + 7 + old_disp == dst + 5 + 7 + new_disp);
}

TEST_CASE("oneshot stub") {
    auto stub = build_oneshot_stub(0x10000, 0x20000, 0x20010, 0x20100, 0x30000);
    int i = 0;
    while (i < static_cast<int>(stub.size())) i += insn_len(std::span(stub).subspan(i));
    REQUIRE(i == static_cast<int>(stub.size()));
    auto jmp = abs_jump(0x30000);
    REQUIRE(std::equal(jmp.begin(), jmp.end(), stub.end() - 14));

    auto gate = std::vector<uint8_t>{0xF0, 0x0F, 0xB0, 0x0A};
    auto at = std::search(stub.begin(), stub.end(), gate.begin(), gate.end());
    REQUIRE(at != stub.end());
    REQUIRE(stub[0] == 0x51);
    REQUIRE(stub[1] == 0x52);
    size_t jne = static_cast<size_t>(at - stub.begin()) + gate.size();
    REQUIRE(stub[jne] == 0x5A);
    REQUIRE(stub[jne + 1] == 0x59);
    jne += 2;
    REQUIRE(stub[jne] == 0x0F);
    REQUIRE(stub[jne + 1] == 0x85);
    int32_t rel = load_le<int32_t>(stub.data() + jne + 2);
    int target = static_cast<int>(jne + 6 + rel);
    REQUIRE(target == static_cast<int>(stub.size()) - 14);

    auto no_main = build_oneshot_stub(0x10000, 0x20000, std::nullopt, 0x20100, 0x30000);
    REQUIRE(std::search(no_main.begin(), no_main.end(), std::vector<uint8_t>{0x48, 0xB9}.begin(),
                        std::vector<uint8_t>{0x48, 0xB9}.end()) == no_main.end());
}

namespace {

struct StubRun {
    std::vector<uint64_t> calls;
    uint64_t transfer = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
};

uint64_t imm64(const std::vector<uint8_t>& code, size_t at) {
    if (at + 8 > code.size()) throw std::runtime_error("truncated imm64");
    return load_le<uint64_t>(code.data() + at);
}

StubRun execute_stub(const std::vector<uint8_t>& code, std::unordered_map<uint64_t, uint8_t>& mem) {
    StubRun run;
    uint64_t rax = 0;
    uint64_t rcx = 0x1111111111110001ull;
    uint64_t rdx = 0x2222222222220002ull;
    bool zf = false;
    std::vector<uint64_t> stack;
    size_t ip = 0;
    auto need = [&](size_t n) {
        if (ip + n > code.size()) throw std::runtime_error("truncated stub opcode");
    };
    while (ip < code.size()) {
        need(1);
        uint8_t op = code[ip];
        if (op == 0x48) {
            need(2);
            if (code[ip + 1] == 0xB8) {
                rax = imm64(code, ip + 2);
                ip += 10;
            } else if (code[ip + 1] == 0xBA) {
                rdx = imm64(code, ip + 2);
                ip += 10;
            } else if (code[ip + 1] == 0xB9) {
                ip += 10;
            } else if (code[ip + 1] == 0x83) {
                need(4);
                if ((code[ip + 2] != 0xEC && code[ip + 2] != 0xC4) || code[ip + 3] != 0x28) {
                    throw std::runtime_error("unexpected alu imm8");
                }
                ip += 4;
            } else {
                throw std::runtime_error("unexpected rex.w opcode");
            }
        } else if (op == 0x31) {
            need(2);
            if (code[ip + 1] != 0xC0) throw std::runtime_error("unexpected xor");
            rax = 0;
            ip += 2;
        } else if (op == 0xB1) {
            need(2);
            rcx = (rcx & ~0xFFull) | code[ip + 1];
            ip += 2;
        } else if (op == 0xF0) {
            need(4);
            if (code[ip + 1] != 0x0F || code[ip + 2] != 0xB0 || code[ip + 3] != 0x0A) {
                throw std::runtime_error("unexpected lock cmpxchg");
            }
            uint8_t cur = mem[rdx];
            if (static_cast<uint8_t>(rax) == cur) {
                mem[rdx] = static_cast<uint8_t>(rcx);
                zf = true;
            } else {
                rax = (rax & ~0xFFull) | cur;
                zf = false;
            }
            ip += 4;
        } else if (op == 0x51) {
            stack.push_back(rcx);
            ip += 1;
        } else if (op == 0x52) {
            stack.push_back(rdx);
            ip += 1;
        } else if (op == 0x59) {
            if (stack.empty()) throw std::runtime_error("pop rcx on an empty stack");
            rcx = stack.back();
            stack.pop_back();
            ip += 1;
        } else if (op == 0x5A) {
            if (stack.empty()) throw std::runtime_error("pop rdx on an empty stack");
            rdx = stack.back();
            stack.pop_back();
            ip += 1;
        } else if (op == 0x80) {
            need(3);
            if (code[ip + 1] != 0x38 || code[ip + 2] != 0x01) throw std::runtime_error("unexpected cmp");
            zf = mem[rax] == 1;
            ip += 3;
        } else if (op == 0x0F) {
            need(6);
            if (code[ip + 1] != 0x84 && code[ip + 1] != 0x85) {
                throw std::runtime_error("unexpected 0f opcode");
            }
            int32_t rel = load_le<int32_t>(code.data() + ip + 2);
            size_t next = ip + 6;
            bool take = code[ip + 1] == 0x84 ? zf : !zf;
            ip = take ? static_cast<size_t>(static_cast<int64_t>(next) + rel) : next;
        } else if (op == 0x41) {
            need(2);
            uint8_t mod = code[ip + 1];
            if (mod != 0x50 && mod != 0x51 && mod != 0x58 && mod != 0x59) {
                throw std::runtime_error("unexpected rex push");
            }
            ip += 2;
        } else if (op == 0x4D) {
            need(3);
            if (code[ip + 1] != 0x31 || code[ip + 2] != 0xC0) throw std::runtime_error("unexpected xor");
            ip += 3;
        } else if (op == 0xC6) {
            need(3);
            if (code[ip + 1] != 0x00 || code[ip + 2] != 0x01) throw std::runtime_error("unexpected store");
            mem[rax] = 1;
            ip += 3;
        } else if (op == 0xFF) {
            need(2);
            if (code[ip + 1] == 0xD0) {
                run.calls.push_back(rax);
                ip += 2;
            } else if (code[ip + 1] == 0x25) {
                need(14);
                run.transfer = imm64(code, ip + 6);
                run.rcx = rcx;
                run.rdx = rdx;
                return run;
            } else {
                throw std::runtime_error("unexpected ff opcode");
            }
        } else {
            throw std::runtime_error("unhandled stub opcode");
        }
    }
    throw std::runtime_error("stub fell off the end");
}

} // namespace

TEST_CASE("oneshot stub executes once") {
    constexpr uint64_t flag = 0x10000;
    constexpr uint64_t dll_base = 0x20000;
    constexpr uint64_t dll_main = 0x20010;
    constexpr uint64_t exp = 0x20100;
    constexpr uint64_t tramp = 0x30000;

    auto stub = build_oneshot_stub(flag, dll_base, dll_main, exp, tramp);
    std::unordered_map<uint64_t, uint8_t> mem{{flag, 0}};
    auto first = execute_stub(stub, mem);
    REQUIRE(first.calls == std::vector<uint64_t>({dll_main, exp}));
    REQUIRE(first.transfer == tramp);
    REQUIRE(mem[flag] == 1);

    auto second = execute_stub(stub, mem);
    REQUIRE(second.calls.empty());
    REQUIRE(second.transfer == tramp);
    REQUIRE(first.rcx == 0x1111111111110001ull);
    REQUIRE(first.rdx == 0x2222222222220002ull);
    REQUIRE(second.rcx == 0x1111111111110001ull);
    REQUIRE(second.rdx == 0x2222222222220002ull);

    auto no_main = build_oneshot_stub(flag, dll_base, std::nullopt, exp, tramp);
    std::unordered_map<uint64_t, uint8_t> bare{{flag, 0}};
    auto only = execute_stub(no_main, bare);
    REQUIRE(only.calls == std::vector<uint64_t>({exp}));
    REQUIRE(only.transfer == tramp);
    REQUIRE(bare[flag] == 1);
}

TEST_CASE("external rel8 that does not fit throws") {
    std::vector<uint8_t> code = {0x75, 0x10};
    REQUIRE_THROWS_AS(relocate_stolen(code, 0x1000, 0x2000), HookError);
}

TEST_CASE("external rel32 that does not fit throws") {
    std::vector<uint8_t> code = {0xE9, 0x01, 0x00, 0x00, 0x00};
    REQUIRE_THROWS_AS(relocate_stolen(code, 0, 0x100000000ull), HookError);
}

TEST_CASE("external rel32 beyond 2GB uses an absolute island") {
    std::vector<uint8_t> code = {0xE9, 0x01, 0x00, 0x00, 0x00};
    uint64_t src = 0x7ffaa17f1800ull;
    uint64_t dst = 0x1000000100ull;
    uint64_t target = src + 5 + 1;
    std::vector<FarBranch> far;
    auto body = relocate_stolen(code, src, dst, &far);
    REQUIRE(far.size() == 1);
    REQUIRE(far[0].target == target);
    auto tramp = link_trampoline(body, far, dst, src + code.size());
    int32_t disp = load_le<int32_t>(tramp.data() + 1);
    uint64_t island = dst + 5 + disp;
    REQUIRE(island > dst + code.size());
    REQUIRE(std::vector<uint8_t>(tramp.begin() + static_cast<std::ptrdiff_t>(island - dst),
                                 tramp.begin() + static_cast<std::ptrdiff_t>(island - dst) + 14) ==
            abs_jump(target));
}

TEST_CASE("external rel32 that fits keeps the target") {
    uint64_t src = 0x1000;
    uint64_t dst = 0x2000;
    constexpr uint64_t end = 5;
    int32_t old_disp = 0x100;
    std::vector<uint8_t> code = {0xE9};
    append_i32(code, old_disp);
    auto out = relocate_stolen(code, src, dst);
    int32_t new_disp = load_le<int32_t>(out.data() + 1);
    REQUIRE(src + end + old_disp == dst + end + new_disp);
}
