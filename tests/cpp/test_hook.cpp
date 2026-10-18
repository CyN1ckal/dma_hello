// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/hook.hpp"
#include "dma_hello/mm/page_tables.hpp"
#include "dma_hello/x64.hpp"
#include "fake_memory.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace dma_hello;
using namespace dma_hello::test;

namespace {

constexpr uint64_t kHookVa = 0x7FFE1000;
constexpr uint64_t kStubPage = 0x20002000;
constexpr uint64_t kOldFrame = 0x5000;
constexpr uint64_t kCowFrame = 0x6000;
constexpr uint64_t kStubFrame = 0x7000;

class ProcMemory : public PhysMemory {
public:
    uint64_t cr3_ = 0x1000;
    uint64_t hook_va_ = kHookVa;
    int export_calls = 0;
    std::string export_module;
    std::string export_function;
    std::optional<size_t> short_read;

    std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                              uint32_t pid = 0) override {
        if (!physical && short_read && address == hook_va_) {
            return std::vector<uint8_t>(*short_read, 0x90);
        }
        if (!physical) {
            try {
                std::vector<uint8_t> buf;
                buf.reserve(size);
                size_t off = 0;
                while (off < size) {
                    uint64_t addr = address + off;
                    size_t n = (std::min)(size - off, static_cast<size_t>(kPageSize - (addr & kPageMask)));
                    uint64_t pa = virt_to_phys(*this, cr3_, addr);
                    auto chunk = PhysMemory::read(pa, n, true, pid);
                    buf.insert(buf.end(), chunk.begin(), chunk.end());
                    off += n;
                }
                return buf;
            } catch (const MappingError&) {
            }
        }
        return PhysMemory::read(address, size, physical, pid);
    }

    void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
               uint32_t pid = 0) override {
        if (!physical) {
            try {
                std::vector<std::pair<uint64_t, size_t>> parts;
                size_t off = 0;
                while (off < data.size()) {
                    uint64_t addr = address + off;
                    size_t n =
                        (std::min)(data.size() - off, static_cast<size_t>(kPageSize - (addr & kPageMask)));
                    parts.emplace_back(virt_to_phys(*this, cr3_, addr), n);
                    off += n;
                }
                off = 0;
                for (auto [pa, n] : parts) {
                    PhysMemory::write(pa, data.subspan(off, n), true, pid);
                    off += n;
                }
                return;
            } catch (const MappingError&) {
            }
        }
        PhysMemory::write(address, data, physical, pid);
    }

    uint64_t export_addr(uint32_t, const std::string& module, const std::string& function) override {
        ++export_calls;
        export_module = module;
        export_function = function;
        return hook_va_;
    }

    std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override { return {}; }
};

void plant_pages(ProcMemory& mem) {
    std::vector<uint8_t> nops(kPageSize, 0x90);
    mem.plant_4k(mem.cr3_, mem.hook_va_, kOldFrame, nops, {0x10, 0x11, 0x12});
    std::vector<uint8_t> stub(kPageSize, 0);
    mem.plant_4k(mem.cr3_, kStubPage, kStubFrame, stub, {0x20, 0x21, 0x22});
}

Allocation make_alloc(std::vector<uint64_t> spare) {
    Allocation a;
    a.va = 0x20000000;
    a.size = 0x3000;
    a.pages.spare = std::move(spare);
    a.pages.pfn_database = 0xA00000;
    return a;
}

Target make_target() {
    Target t;
    t.pid = 0x1234;
    t.cr3 = 0x1000;
    return t;
}

PeImage make_pe() {
    PeImage pe;
    pe.size_of_image = 0x1000;
    pe.exports["LaunchHello"] = 0x100;
    pe.entry_rva = 0x200;
    return pe;
}

} // namespace

TEST_CASE("install refuses GetTickCount") {
    KernelMemory mem;
    Target t;
    Allocation a;
    PeImage pe;
    REQUIRE_THROWS_AS(install_hook(mem, t, a, pe, "kernel32.dll", "GetTickCount", "LaunchHello"),
                      HookError);
    REQUIRE_THROWS_AS(
        install_hook(mem, t, a, pe, "kernelbase.dll", "GetTickCount64", "LaunchHello"), HookError);
}

TEST_CASE("overlapping stub is not written into the image") {
    class HookMemory : public KernelMemory {
    public:
        uint64_t export_addr(uint32_t, const std::string&, const std::string&) override {
            return 0x1000;
        }
        std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override {
            return {{0x200000, 0x200FFF}};
        }
    } mem;
    std::fill(mem.mem.begin() + 0x1000, mem.mem.begin() + 0x1020, static_cast<uint8_t>(0x90));
    Target t;
    t.pid = 4;
    Allocation a;
    a.va = 0x200000;
    a.size = 0x2000;
    PeImage pe;
    pe.size_of_image = 0x3000;
    pe.exports["LaunchHello"] = 0x1000;
    REQUIRE_THROWS_AS(install_hook(mem, t, a, pe, "user32.dll", "MessageBoxA", "LaunchHello"),
                      HookError);
    REQUIRE(a.size == 0x2000);
}

TEST_CASE("install hook cows the prologue") {
    class OrderMemory : public ProcMemory {
    public:
        std::vector<uint64_t> writes;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            writes.push_back(address);
            ProcMemory::write(address, data, physical, pid);
        }
    } mem;
    plant_pages(mem);
    mem.writes.clear();
    auto t = make_target();
    auto a = make_alloc({kCowFrame});
    auto pe = make_pe();
    auto h = install_hook(mem, t, a, pe, "user32.dll", "MessageBoxA", "LaunchHello");

    REQUIRE(mem.export_calls == 1);
    REQUIRE(mem.export_module == "user32.dll");
    REQUIRE(mem.export_function == "messageboxa");
    REQUIRE(h.address == kHookVa);
    REQUIRE(h.stolen >= 14);
    REQUIRE(h.cow_frame == kCowFrame);
    REQUIRE(h.stub_va >= kStubPage);
    REQUIRE(h.stub_va < kStubPage + kPageSize);
    REQUIRE(h.trampoline_va >= kStubPage);
    REQUIRE(h.trampoline_va < kStubPage + kPageSize);

    auto orig = mem.read(kOldFrame << 12, kPageSize, true);
    REQUIRE(orig == std::vector<uint8_t>(kPageSize, 0x90));

    uint64_t hook_pa = (kCowFrame << 12) | (kHookVa & kPageMask);
    auto patched = mem.read(hook_pa, 14, true);
    REQUIRE(patched[0] == 0xFF);
    REQUIRE(patched[1] == 0x25);
    REQUIRE(load_le<uint64_t>(patched.data() + 6) == h.stub_va);

    auto slot = existing_pte_slot(mem, t.cr3, kHookVa);
    REQUIRE(slot);
    REQUIRE((slot->pte & kPteAddrMask) == (kCowFrame << 12));
    REQUIRE(slot->pte & kPteP);
    REQUIRE(slot->pte & kPteRw);

    auto tramp = mem.read(h.trampoline_va, static_cast<size_t>(h.stolen) + 14, false);
    REQUIRE(std::all_of(tramp.begin(), tramp.begin() + h.stolen, [](uint8_t b) { return b == 0x90; }));
    auto back = encode_jump(h.trampoline_va + static_cast<uint64_t>(h.stolen),
                            h.address + static_cast<uint64_t>(h.stolen));
    REQUIRE(std::equal(back.begin(), back.end(), tramp.begin() + h.stolen));

    uint64_t state = a.pages.pfn_database + kCowFrame * 0x30 + 0x22;
    auto active = std::find(mem.writes.begin(), mem.writes.end(), state);
    auto pte = std::find(mem.writes.begin(), mem.writes.end(), slot->slot_pa);
    REQUIRE(active != mem.writes.end());
    REQUIRE(pte != mem.writes.end());
    REQUIRE(active < pte);

    mem.writes.clear();
    REQUIRE_THROWS_WITH(install_hook(mem, t, a, pe, "user32.dll", "MessageBoxA", "LaunchHello"),
                        "MessageBoxA is already hooked; refusing a second COW");
}

TEST_CASE("GetTickCount refusal does not resolve the export") {
    ProcMemory mem;
    auto t = make_target();
    auto a = make_alloc({kCowFrame});
    auto pe = make_pe();
    REQUIRE_THROWS_AS(install_hook(mem, t, a, pe, "KERNEL32.DLL", "GetTickCount", "LaunchHello"),
                      HookError);
    REQUIRE(mem.export_calls == 0);
}

TEST_CASE("install without a spare frame leaves the prologue") {
    ProcMemory mem;
    plant_pages(mem);
    auto before = mem.read(kOldFrame << 12, kPageSize, true);
    auto t = make_target();
    auto a = make_alloc({});
    auto pe = make_pe();
    REQUIRE_THROWS_AS(install_hook(mem, t, a, pe, "user32.dll", "MessageBoxA", "LaunchHello"),
                      HookError);
    REQUIRE(mem.read(kOldFrame << 12, kPageSize, true) == before);
}

TEST_CASE("far hook uses a 5-byte jump and leaves the resume byte") {
    class FarMemory : public ProcMemory {
    public:
        FarMemory() { hook_va_ = 0x7FF000010000ull; }
        std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override {
            return {{0x7FF000010000ull, 0x7FF000020FFFull}};
        }
    } mem;
    constexpr uint64_t kFar = 0x7FF000010000ull;
    constexpr uint64_t kCavePage = 0x7FF000020000ull;
    constexpr uint64_t kCaveSrc = 0x5100;
    constexpr uint64_t kCaveCow = 0x8000;
    const uint8_t prologue[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
                                0x48, 0x89, 0x74, 0x24, 0x18, 0x57};
    std::vector<uint8_t> hook_page(kPageSize, 0x90);
    std::copy(std::begin(prologue), std::end(prologue), hook_page.begin());
    std::vector<uint64_t> tables = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    auto left = mem.plant_4k(mem.cr3_, kFar, kOldFrame, hook_page, tables);
    std::vector<uint8_t> padding(kPageSize, 0xCC);
    mem.plant_4k(mem.cr3_, kCavePage, kCaveSrc, padding, left);

    auto t = make_target();
    auto a = make_alloc({kCowFrame, kCaveCow});
    auto pe = make_pe();
    auto h = install_hook(mem, t, a, pe, "user32.dll", "PeekMessageW", "LaunchHello");

    REQUIRE(h.stolen == 5);
    uint64_t hook_pa = (kCowFrame << 12) | (kFar & kPageMask);
    auto patched = mem.read(hook_pa, 16, true);
    REQUIRE(patched[0] == 0xE9);
    REQUIRE(patched[5] == 0x48);
    REQUIRE(patched[6] == 0x89);
    REQUIRE(patched[7] == 0x6C);
    int32_t rel = load_le<int32_t>(patched.data() + 1);
    uint64_t cave = kFar + 5 + static_cast<int64_t>(rel);
    REQUIRE(cave == kCavePage);
    auto island = mem.read((kCaveCow << 12) | (cave & kPageMask), 14, true);
    REQUIRE(island[0] == 0xFF);
    REQUIRE(island[1] == 0x25);
    REQUIRE(load_le<uint64_t>(island.data() + 6) == h.stub_va);

    auto tramp = mem.read(h.trampoline_va, 5, false);
    REQUIRE(std::equal(std::begin(prologue), std::begin(prologue) + 5, tramp.begin()));

    auto shared = mem.read(kOldFrame << 12, 5, true);
    REQUIRE(std::equal(std::begin(prologue), std::begin(prologue) + 5, shared.begin()));

    REQUIRE_THROWS_WITH(install_hook(mem, t, a, pe, "user32.dll", "PeekMessageW", "LaunchHello"),
                        "PeekMessageW is already hooked; refusing a second COW");
}

TEST_CASE("existing overlay detour is chained") {
    class FarMemory : public ProcMemory {
    public:
        FarMemory() { hook_va_ = 0x7FF000010000ull; }
        std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t) override {
            return {{0x7FF000010000ull, 0x7FF00004FFFFull}};
        }
    } mem;
    constexpr uint64_t kFar = 0x7FF000010000ull;
    constexpr uint64_t kPad = 0x7FF000020000ull;
    constexpr uint64_t kForeign = 0x7FF000030000ull;
    constexpr uint64_t kOverlay = 0x7FF000040000ull;
    constexpr uint64_t kForeignSrc = 0x5200;
    constexpr uint64_t kOverlaySrc = 0x5300;
    constexpr uint64_t kCaveCow = 0x8000;

    std::vector<uint8_t> hook_page(kPageSize, 0x90);
    // E9 to the foreign cave, then the real second instruction of PeekMessageW.
    int32_t rel = static_cast<int32_t>(kForeign - (kFar + 5));
    hook_page[0] = 0xE9;
    store_le(hook_page.data() + 1, rel);
    const uint8_t rest[] = {0x48, 0x89, 0x6C, 0x24, 0x10};
    std::copy(std::begin(rest), std::end(rest), hook_page.begin() + 5);

    std::vector<uint8_t> foreign(kPageSize, 0);
    auto island = abs_jump(kOverlay);
    std::copy(island.begin(), island.end(), foreign.begin());
    std::vector<uint8_t> overlay(kPageSize, 0xC3);
    const uint8_t handler[] = {0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56};
    std::copy(std::begin(handler), std::end(handler), overlay.begin());
    std::vector<uint8_t> padding(kPageSize, 0xCC);

    std::vector<uint64_t> tables = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
    auto left = mem.plant_4k(mem.cr3_, kFar, kOldFrame, hook_page, tables);
    left = mem.plant_4k(mem.cr3_, kPad, 0x5400, padding, left);
    left = mem.plant_4k(mem.cr3_, kForeign, kForeignSrc, foreign, left);
    mem.plant_4k(mem.cr3_, kOverlay, kOverlaySrc, overlay, left);

    auto t = make_target();
    auto a = make_alloc({kCowFrame, kCaveCow});
    auto pe = make_pe();
    auto h = install_hook(mem, t, a, pe, "user32.dll", "PeekMessageW", "LaunchHello");

    REQUIRE(h.stolen == 5);
    auto patched = mem.read((kCowFrame << 12) | (kFar & kPageMask), 10, true);
    REQUIRE(patched[0] == 0xE9);
    REQUIRE(patched[5] == 0x48);
    REQUIRE(patched[6] == 0x89);

    auto tramp = mem.read(h.trampoline_va, 32, false);
    REQUIRE(tramp[0] == 0xE9);
    int32_t tramp_rel = load_le<int32_t>(tramp.data() + 1);
    uint64_t landed = h.trampoline_va + 5 + static_cast<int64_t>(tramp_rel);
    auto at = mem.read(landed, 14, false);
    REQUIRE(at[0] == 0xFF);
    REQUIRE(at[1] == 0x25);
    REQUIRE(load_le<uint64_t>(at.data() + 6) == kForeign);

    REQUIRE_THROWS_WITH(install_hook(mem, t, a, pe, "user32.dll", "PeekMessageW", "LaunchHello"),
                        "PeekMessageW is already hooked; refusing a second COW");
}

TEST_CASE("short prologue read throws") {
    ProcMemory mem;
    plant_pages(mem);
    mem.short_read = 13;
    auto t = make_target();
    auto a = make_alloc({kCowFrame});
    auto pe = make_pe();
    REQUIRE_THROWS_AS(install_hook(mem, t, a, pe, "user32.dll", "MessageBoxA", "LaunchHello"),
                      HookError);
}
