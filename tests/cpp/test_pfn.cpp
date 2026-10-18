// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "fake_memory.hpp"

#include <cstring>

using namespace dma_hello;
using namespace dma_hello::test;

namespace {

struct UnlinkFixture {
    KernelMemory session;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000;
    uint64_t head = 0x20000;
    uint64_t p1 = 0x200, p2 = 0x201, p3 = 0x202;

    uint64_t entry(uint64_t pfn) { return db + pfn * layout.size; }

    void set_loc(uint64_t pfn, uint8_t loc) { session.mem[entry(pfn) + layout.u3 + 2] = loc; }

    void set_links(uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(session.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(session.mem.data() + entry(pfn) + layout.u2, bl);
    }

    void chain(uint64_t a, uint64_t b, uint64_t c, uint64_t total = 3) {
        set_links(a, b, kPfnTerminator);
        set_links(b, c, a);
        set_links(c, kPfnTerminator, b);
        set_loc(a, kFreePageList);
        set_loc(b, kFreePageList);
        set_loc(c, kFreePageList);
        store_le(session.mem.data() + head + lists.total, total);
        store_le(session.mem.data() + head + lists.flink, a);
        store_le(session.mem.data() + head + lists.blink, c);
    }

    bool unlink(uint64_t pfn) {
        std::unordered_map<int, uint64_t> h{{kFreePageList, head}};
        return unlink_one(session, db, layout, lists, pfn, h, kFreePageList);
    }

    uint64_t flink_of(uint64_t pfn) {
        return *session.read_u64(entry(pfn) + layout.u1) & kPfnMask;
    }
    uint64_t blink_of(uint64_t pfn) {
        return *session.read_u64(entry(pfn) + layout.u2) & kPfnMask;
    }
};

} // namespace

TEST_CASE("pfn bits") {
    REQUIRE(kPfnBits == 40);
    REQUIRE(kPfnTerminator == (1ull << 40) - 1);
    REQUIRE(set_low_pfn(0xFFFF000000000000ull, 0xABC) == 0xFFFF000000000ABCull);
    REQUIRE(set_low_pfn(0xFFFF000000000000ull, (1ull << 36) | 0xABC) == 0xFFFF001000000ABCull);
    REQUIRE(on_free_list(0));
    REQUIRE(on_free_list(1));
    REQUIRE_FALSE(on_free_list(6));
}

TEST_CASE("interior unlink") {
    UnlinkFixture f;
    f.chain(f.p1, f.p2, f.p3);
    REQUIRE(f.unlink(f.p2));
    REQUIRE(f.flink_of(f.p1) == f.p3);
    REQUIRE(f.blink_of(f.p3) == f.p1);
    REQUIRE(*f.session.read_u64(f.head + f.lists.total) == 2);

    auto detached = f.session.mem;
    REQUIRE_FALSE(f.unlink(f.p2));
    REQUIRE(f.session.mem == detached);
    REQUIRE(*f.session.read_u64(f.head + f.lists.total) == 2);
}

TEST_CASE("head and tail unlink") {
    UnlinkFixture f;
    f.chain(f.p1, f.p2, f.p3);
    uint64_t decorated = f.p1 | (0x5Aull << 40);
    store_le(f.session.mem.data() + f.entry(f.p2) + f.layout.u2, decorated);
    REQUIRE(f.unlink(f.p1));
    REQUIRE(*f.session.read_u64(f.head + f.lists.flink) == f.p2);
    REQUIRE(f.blink_of(f.p2) == kPfnTerminator);
    REQUIRE((*f.session.read_u64(f.entry(f.p2) + f.layout.u2) & ~kPfnMask) == (0x5Aull << 40));

    UnlinkFixture t;
    t.chain(t.p1, t.p2, t.p3);
    REQUIRE(t.unlink(t.p3));
    REQUIRE(*t.session.read_u64(t.head + t.lists.blink) == t.p2);
    REQUIRE(t.flink_of(t.p2) == kPfnTerminator);
}

TEST_CASE("singleton unlink") {
    UnlinkFixture f;
    f.set_links(f.p1, kPfnTerminator, kPfnTerminator);
    f.set_loc(f.p1, kFreePageList);
    store_le(f.session.mem.data() + f.head + f.lists.total, uint64_t{1});
    store_le(f.session.mem.data() + f.head + f.lists.flink, f.p1);
    store_le(f.session.mem.data() + f.head + f.lists.blink, f.p1);
    REQUIRE(f.unlink(f.p1));
    REQUIRE(*f.session.read_u64(f.head + f.lists.flink) == kPfnTerminator);
    REQUIRE(*f.session.read_u64(f.head + f.lists.total) == 0);
}

TEST_CASE("refuse active neighbors") {
    UnlinkFixture f;
    f.chain(f.p1, f.p2, f.p3);
    f.set_loc(f.p2, kActiveAndValid);
    auto before = f.session.mem;
    REQUIRE_FALSE(f.unlink(f.p2));
    REQUIRE(f.session.mem == before);

    f.chain(f.p1, f.p2, f.p3);
    f.set_loc(f.p3, kActiveAndValid);
    before = f.session.mem;
    REQUIRE_FALSE(f.unlink(f.p2));
    REQUIRE(f.session.mem == before);

    f.chain(f.p1, f.p2, f.p3);
    f.set_loc(f.p1, kActiveAndValid);
    before = f.session.mem;
    REQUIRE_FALSE(f.unlink(f.p2));
    REQUIRE(f.session.mem == before);
}

TEST_CASE("no heads refuses") {
    UnlinkFixture f;
    f.chain(f.p1, f.p2, f.p3);
    auto before = f.session.mem;
    std::unordered_map<int, uint64_t> empty;
    REQUIRE_FALSE(unlink_one(f.session, f.db, f.layout, f.lists, f.p2, empty, kFreePageList));
    REQUIRE(f.session.mem == before);
}

TEST_CASE("unlink rollback with flaky dma") {
    FlakyKernel mem(3);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    auto set_loc = [&](uint64_t pfn, uint8_t loc) { mem.mem[entry(pfn) + layout.u3 + 2] = loc; };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    set_loc(p1, kFreePageList);
    set_loc(p2, kFreePageList);
    set_loc(p3, kFreePageList);
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    auto before = mem.mem;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE(mem.mem == before);
}

TEST_CASE("unlink rollback failure is not a soft miss") {
    class TornKernel : public KernelMemory {
    public:
        int writes = 0;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            ++writes;
            if (writes == 3) throw SessionError("dma glitch");
            if (writes > 3) throw SessionError("restore failed");
            KernelMemory::write(address, data, physical, pid);
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_THROWS_AS(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList),
                      PfnRollbackError);
}

TEST_CASE("link readback with flag bits above the pfn still unlinks") {
    class FlagAfterWrite : public KernelMemory {
    public:
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            KernelMemory::write(address, data, physical, pid);
            if (data.size() != 8 || address + 8 > mem.size()) return;
            uint64_t value = load_le<uint64_t>(mem.data() + address);
            if ((value & kPfnMask) < 0x100) return;
            store_le(mem.data() + address, value | (1ull << 40));
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == p3);
    REQUIRE((*mem.read_u64(entry(p3) + layout.u2) & kPfnMask) == p1);
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & ~kPfnMask) == (1ull << 40));
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == p3);
    REQUIRE((*mem.read_u64(entry(p2) + layout.u2) & kPfnMask) == p1);
    REQUIRE(load_le<uint64_t>(mem.mem.data() + head + lists.total) == 2);
}

TEST_CASE("a stale first readback still counts the unlink") {
    class StaleOnce : public KernelMemory {
    public:
        std::unordered_map<uint64_t, uint64_t> pending;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            if (data.size() == 8 && address + 8 <= mem.size()) {
                pending[address] = load_le<uint64_t>(mem.data() + address);
            }
            KernelMemory::write(address, data, physical, pid);
        }
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto it = pending.find(address);
            if (it != pending.end() && size >= 8) {
                uint64_t old = it->second;
                pending.erase(it);
                auto out = KernelMemory::read(address, size, physical, pid);
                store_le(out.data(), old);
                return out;
            }
            return KernelMemory::read(address, size, physical, pid);
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == p3);
    REQUIRE(load_le<uint64_t>(mem.mem.data() + head + lists.total) == 2);
}

TEST_CASE("total drift of a few pages still unlinks") {
    class DriftTotal : public KernelMemory {
    public:
        uint64_t total_addr = 0;
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto out = KernelMemory::read(address, size, physical, pid);
            if (address == total_addr && out.size() >= 8) {
                uint64_t value = load_le<uint64_t>(out.data());
                if (value == 2) store_le(out.data(), uint64_t{1});
            }
            return out;
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    mem.total_addr = head + lists.total;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE(load_le<uint64_t>(mem.mem.data() + head + lists.total) == 2);
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == p3);
}

TEST_CASE("unlink rollback leaves a qword the kernel replaced") {
    class ReplacedLink : public KernelMemory {
    public:
        int writes = 0;
        uint64_t watch = 0;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            ++writes;
            if (writes == 3) {
                store_le(mem.data() + watch, uint64_t{0x999});
                throw SessionError("dma glitch");
            }
            KernelMemory::write(address, data, physical, pid);
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    mem.watch = entry(p1) + layout.u1;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_THROWS_AS(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList),
                      PfnRollbackError);
    REQUIRE(*mem.read_u64(mem.watch) == 0x999);
}

TEST_CASE("stale list total is not published") {
    class EarlyTotal : public KernelMemory {
    public:
        uint64_t total_addr = 0;
        int total_reads = 0;
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto out = KernelMemory::read(address, size, physical, pid);
            if (address != total_addr || out.size() < 8) return out;
            ++total_reads;
            if (total_reads == 1) store_le(out.data(), uint64_t{100});
            return out;
        }
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            if (address == total_addr && data.size() >= 8) {
                uint64_t value = load_le<uint64_t>(data.data());
                uint64_t live = load_le<uint64_t>(mem.data() + address);
                if (value > live) throw SessionError("stale total published");
            }
            KernelMemory::write(address, data, physical, pid);
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    mem.total_addr = head + lists.total;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE(load_le<uint64_t>(mem.mem.data() + head + lists.total) == 2);
}

TEST_CASE("page that leaves the free list is not unlinked") {
    class LeaveList : public KernelMemory {
    public:
        uint64_t watch = 0;
        int hits = 0;
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto out = KernelMemory::read(address, size, physical, pid);
            if (address == watch && !out.empty()) {
                ++hits;
                if (hits >= 2) out[0] = static_cast<uint8_t>(kActiveAndValid);
            }
            return out;
        }
    } mem;
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    mem.watch = entry(p2) + layout.u3 + 2;
    auto before = mem.mem;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList));
    REQUIRE(mem.mem == before);
}

TEST_CASE("empty physical map refuses the claim") {
    class MapMemory : public KernelMemory {
    public:
        std::optional<uint64_t> symbol(const char* name) override {
            if (name && std::strcmp(name, "MmPfnDatabase") == 0) return 0x1000;
            return std::nullopt;
        }
        std::vector<std::pair<uint64_t, uint64_t>> phys_map() override { return {}; }
    } mem;
    store_le(mem.mem.data() + 0x1000, 0xFFFFF80000000000ull);
    REQUIRE_THROWS_WITH(allocate_physical_pages(mem, 0x1000),
                        "physical memory map is empty; refusing to scan PFNs");
}

namespace {

class ColorKernel : public KernelMemory {
public:
    std::unordered_map<std::string, uint64_t> symbols;
    std::unordered_map<std::string, std::unordered_map<std::string, int>> fields;
    std::unordered_map<std::string, int> sizes;

    std::optional<uint64_t> symbol(const char* name) override {
        auto it = symbols.find(name ? name : "");
        if (it == symbols.end()) return std::nullopt;
        return it->second;
    }
    std::optional<int> type_size(const char* type) override {
        auto it = sizes.find(type ? type : "");
        if (it == sizes.end()) return std::nullopt;
        return it->second;
    }
    std::optional<int> field_offset(const char* type, const char* field) override {
        auto type_it = fields.find(type ? type : "");
        if (type_it == fields.end()) return std::nullopt;
        auto field_it = type_it->second.find(field ? field : "");
        if (field_it == type_it->second.end()) return std::nullopt;
        return field_it->second;
    }
};

void plant_color_types(ColorKernel& mem) {
    mem.symbols["MiState"] = 0x80000;
    mem.symbols["MmNumberOfChannels"] = 0x88040;
    mem.symbols["MiPageSizes"] = 0x88000;
    mem.fields["_MI_SYSTEM_INFORMATION"]["Hardware"] = 0x100;
    mem.fields["_MI_SYSTEM_INFORMATION"]["Partitions"] = 0x200;
    mem.fields["_MI_HARDWARE_STATE"]["PageColors"] = 0x20;
    mem.fields["_MI_HARDWARE_STATE"]["NumaMemoryRanges"] = 0x40;
    mem.fields["_MI_HARDWARE_STATE"]["NumaLastRangeIndexInclusive"] = 0x48;
    mem.fields["_MI_HARDWARE_STATE"]["ChannelMemoryRanges"] = 0x50;
    mem.fields["_MI_PARTITION_STATE"]["Partition"] = 0x10;
    mem.fields["_MI_PARTITION"]["Core"] = 0;
    mem.fields["_MI_PARTITION_CORE"]["NodeInformation"] = 0x10;
    mem.fields["_MI_NODE_INFORMATION"]["FreePageInfo"] = 0;
    mem.fields["_MI_NODE_FREE_PAGE_INFORMATION"]["LargePageEntries"] = 0x40;
    mem.sizes["_MI_NODE_INFORMATION"] = 0x1000;
    mem.sizes["_MMPFNLIST"] = 0x58;
    mem.mem[0x88040] = 1;
    store_le(mem.mem.data() + 0x88000 + 24, uint64_t{1});
    store_le(mem.mem.data() + 0x80120 + 12, uint32_t{4});
    store_le(mem.mem.data() + 0x80210, uint64_t{0x81000});
    store_le(mem.mem.data() + 0x81000, uint64_t{0x82000});
    store_le(mem.mem.data() + 0x82010, uint64_t{0x83000});
}

// Free list, cached, 4K, channel 0. Matches MiUnlinkFreeOrZeroedPage's slot.
int test_color_index(int cache, int list) {
    return cache + 4 * (0 + 2 * (list + 2 * (0 + 10 * 3)));
}

} // namespace

TEST_CASE("missing color fields leave the aggregate unlink alone") {
    ColorKernel mem;
    auto account = color_account(mem);
    REQUIRE_FALSE(account.enabled);
    UnlinkFixture f;
    f.chain(f.p1, f.p2, f.p3);
    REQUIRE(f.unlink(f.p2));
    REQUIRE(f.flink_of(f.p2) == f.p3);
    REQUIRE(f.blink_of(f.p2) == f.p1);
}

TEST_CASE("color list total drops for the tail") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    REQUIRE(account.enabled);
    REQUIRE(account.page_colors == 4);

    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == kKernelListEnd);
    REQUIRE((*mem.read_u64(entry(p3) + layout.u1) & kPfnMask) == kPfnTerminator);
    REQUIRE((*mem.read_u64(entry(p3) + layout.u2) & kPfnMask) == p2);
    REQUIRE((*mem.read_u64(color_head + lists.blink) & kPfnMask) == p2);
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == p2);
    REQUIRE(*mem.read_u64(head + lists.total) == 2);
    REQUIRE(*mem.read_u64(color_head + lists.total) == 6);
    REQUIRE(account.decrements == 1);
    REQUIRE(account.aggregate_skips == 0);
    REQUIRE(*mem.read_u64(head + lists.flink) == p1);
}

TEST_CASE("a racing aggregate total does not undo the color splice") {
    class RacingAggregate : public ColorKernel {
    public:
        uint64_t total_addr = 0;
        int hits = 0;
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto out = ColorKernel::read(address, size, physical, pid);
            if (address == total_addr && out.size() >= 8) {
                ++hits;
                store_le(out.data(), uint64_t{100000} + static_cast<uint64_t>(hits) * 1000);
            }
            return out;
        }
    } mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    mem.total_addr = head + lists.total;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == kKernelListEnd);
    REQUIRE((*mem.read_u64(entry(p3) + layout.u1) & kPfnMask) == kPfnTerminator);
    REQUIRE((*mem.read_u64(entry(p3) + layout.u2) & kPfnMask) == p2);
    REQUIRE((*mem.read_u64(color_head + lists.blink) & kPfnMask) == p2);
    REQUIRE(*mem.read_u64(color_head + lists.total) == 6);
    REQUIRE(load_le<uint64_t>(mem.mem.data() + head + lists.total) == 3);
    REQUIRE(account.decrements == 1);
    REQUIRE(account.aggregate_skips == 1);
}

TEST_CASE("u4 bit 40 stays on the 4k color list when the page size adjustment is zero") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + entry(p3) + layout.u4, 1ull << 40);
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    store_le(mem.mem.data() + head + lists.flink, p1);
    store_le(mem.mem.data() + head + lists.blink, p3);
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE(*mem.read_u64(color_head + lists.total) == 6);
    REQUIRE(account.decrements == 1);
    REQUIRE(account.refuse_color == 0);

    store_le(mem.mem.data() + entry(p3) + layout.u3 + 4, uint32_t{1u << 27});
    auto before = mem.mem;
    int skips = account.aggregate_skips;
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE(mem.mem == before);
    REQUIRE(account.refuse_color == 1);
    REQUIRE(account.aggregate_skips == skips);
}

TEST_CASE("color list tail blink is updated and the detached page keeps its links") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x204;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    store_le(mem.mem.data() + entry(p1) + layout.u1, p2);
    store_le(mem.mem.data() + entry(p1) + layout.u2, kKernelListEnd);
    store_le(mem.mem.data() + entry(p2) + layout.u1, kKernelListEnd);
    store_le(mem.mem.data() + entry(p2) + layout.u2, p1);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{2});
    store_le(mem.mem.data() + head + lists.flink, uint64_t{0xABC});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p2 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{2});
    store_le(mem.mem.data() + color_head + lists.flink, p1);
    store_le(mem.mem.data() + color_head + lists.blink, p2);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList, &account));
    REQUIRE(*mem.read_u64(color_head + lists.flink) == p1);
    REQUIRE((*mem.read_u64(color_head + lists.blink) & kPfnMask) == p1);
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == kKernelListEnd);
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == kKernelListEnd);
    REQUIRE((*mem.read_u64(entry(p2) + layout.u2) & kPfnMask) == p1);
    REQUIRE(*mem.read_u64(head + lists.flink) == 0xABC);
    REQUIRE(*mem.read_u64(color_head + lists.total) == 1);
    REQUIRE(*mem.read_u64(head + lists.total) == 1);
}

TEST_CASE("color list refuses a head that is not the tail") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x204;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    store_le(mem.mem.data() + entry(p1) + layout.u1, p2);
    store_le(mem.mem.data() + entry(p1) + layout.u2, kKernelListEnd);
    store_le(mem.mem.data() + entry(p2) + layout.u1, kKernelListEnd);
    store_le(mem.mem.data() + entry(p2) + layout.u2, p1);
    mem.mem[entry(p1) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{2});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p1 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{2});
    store_le(mem.mem.data() + color_head + lists.flink, p1);
    store_le(mem.mem.data() + color_head + lists.blink, p2);
    auto before = mem.mem;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p1, heads, kFreePageList, &account));
    REQUIRE(mem.mem == before);
    REQUIRE(account.decrements == 0);
    REQUIRE(account.refuse_edge == 1);
}

TEST_CASE("a color list that cannot be found is not unlinked") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    store_le(mem.mem.data() + entry(p1) + layout.u1, p2);
    store_le(mem.mem.data() + entry(p1) + layout.u2, kPfnTerminator);
    store_le(mem.mem.data() + entry(p2) + layout.u1, p3);
    store_le(mem.mem.data() + entry(p2) + layout.u2, p1);
    store_le(mem.mem.data() + entry(p3) + layout.u1, kPfnTerminator);
    store_le(mem.mem.data() + entry(p3) + layout.u2, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    auto before = mem.mem;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList, &account));
    REQUIRE(mem.mem == before);
    REQUIRE(account.decrements == 0);
}

TEST_CASE("color list refuses an interior page before touching its total") {
    ColorKernel mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    mem.mem[entry(p3) + layout.u3 + 2] = kFreePageList;
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p2 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    auto before = mem.mem;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p2, heads, kFreePageList, &account));
    REQUIRE(mem.mem == before);
    REQUIRE(account.decrements == 0);
    REQUIRE(account.refuse_edge == 1);
}

TEST_CASE("color total is stored before the tail links") {
    class OrderKernel : public ColorKernel {
    public:
        std::vector<uint64_t> writes;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            writes.push_back(address);
            ColorKernel::write(address, data, physical, pid);
        }
    } mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE_FALSE(mem.writes.empty());
    REQUIRE(mem.writes.front() == color_head + lists.total);
    auto pos = [&](uint64_t addr) {
        for (size_t i = 0; i < mem.writes.size(); ++i) {
            if (mem.writes[i] == addr) return static_cast<int>(i);
        }
        return -1;
    };
    int blink_at = pos(color_head + lists.blink);
    int pred_at = pos(entry(p2) + layout.u1);
    REQUIRE(blink_at > 0);
    REQUIRE(pred_at > blink_at);
    REQUIRE(pos(entry(p3) + layout.u1) < 0);
    REQUIRE(pos(entry(p3) + layout.u2) < 0);
}

TEST_CASE("a color total that reads back low is left low and the tail stays linked") {
    class ShortTotal : public ColorKernel {
    public:
        uint64_t total_addr = 0;
        int total_writes = 0;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            if (address == total_addr) ++total_writes;
            ColorKernel::write(address, data, physical, pid);
        }
        std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                  uint32_t pid = 0) override {
            auto out = ColorKernel::read(address, size, physical, pid);
            if (address == total_addr && total_writes > 0 && out.size() >= 8) {
                store_le(out.data(), load_le<uint64_t>(out.data()) - 1);
            }
            return out;
        }
    } mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    mem.total_addr = color_head + lists.total;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE(mem.total_writes == 1);
    REQUIRE(load_le<uint64_t>(mem.mem.data() + color_head + lists.total) == 6);
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == p3);
    REQUIRE(*mem.read_u64(head + lists.total) == 3);
    REQUIRE(account.decrements == 0);
    REQUIRE(account.refuse_batch == 1);
}

TEST_CASE("a tail that moves after the color total drop is not spliced") {
    class LeaveTail : public ColorKernel {
    public:
        uint64_t total_addr = 0;
        uint64_t flink_addr = 0;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            ColorKernel::write(address, data, physical, pid);
            if (address == total_addr) store_le(mem.data() + flink_addr, uint64_t{0x111});
        }
    } mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200, p2 = 0x201, p3 = 0x202;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    auto set_links = [&](uint64_t pfn, uint64_t fl, uint64_t bl) {
        store_le(mem.mem.data() + entry(pfn) + layout.u1, fl);
        store_le(mem.mem.data() + entry(pfn) + layout.u2, bl);
    };
    set_links(p1, p2, kPfnTerminator);
    set_links(p2, p3, p1);
    set_links(p3, kPfnTerminator, p2);
    mem.mem[entry(p1) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p2) + layout.u3 + 2] = kFreePageList;
    mem.mem[entry(p3) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{3});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p3 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{7});
    store_le(mem.mem.data() + color_head + lists.blink, p3);
    mem.total_addr = color_head + lists.total;
    mem.flink_addr = entry(p3) + layout.u1;
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE_FALSE(unlink_one(mem, db, layout, lists, p3, heads, kFreePageList, &account));
    REQUIRE(*mem.read_u64(color_head + lists.total) == 6);
    REQUIRE((*mem.read_u64(entry(p2) + layout.u1) & kPfnMask) == p3);
    REQUIRE((*mem.read_u64(color_head + lists.blink) & kPfnMask) == p3);
    REQUIRE(*mem.read_u64(head + lists.total) == 3);
    REQUIRE(account.decrements == 1);
    REQUIRE(account.refuse_stale == 1);
}

TEST_CASE("a one page color list publishes the end marker on blink before flink") {
    class OrderKernel : public ColorKernel {
    public:
        std::vector<uint64_t> writes;
        void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                   uint32_t pid = 0) override {
            writes.push_back(address);
            ColorKernel::write(address, data, physical, pid);
        }
    } mem;
    plant_color_types(mem);
    auto account = color_account(mem);
    MmpfnLayout layout{0x30, 0, 8, 0x18, 0x20, 0x28, 0x10};
    MmpfnListLayout lists{0x28, 0, 0x10, 0x18};
    uint64_t db = 0x10000, head = 0x20000, p1 = 0x200;
    auto entry = [&](uint64_t pfn) { return db + pfn * layout.size; };
    store_le(mem.mem.data() + entry(p1) + layout.u1, kKernelListEnd);
    store_le(mem.mem.data() + entry(p1) + layout.u2, kKernelListEnd);
    mem.mem[entry(p1) + layout.u3 + 2] = static_cast<uint8_t>(kFreePageList | (1 << 6));
    store_le(mem.mem.data() + head + lists.total, uint64_t{1});
    const int index = test_color_index(1, kFreePageList);
    const uint64_t slot = 0x83000 + 0x40 + static_cast<uint64_t>(index) * 8;
    store_le(mem.mem.data() + slot, uint64_t{0x90000});
    const uint64_t color_head = 0x90000 + (p1 % 4) * 0x58;
    store_le(mem.mem.data() + color_head + lists.total, uint64_t{1});
    store_le(mem.mem.data() + color_head + lists.flink, p1);
    store_le(mem.mem.data() + color_head + lists.blink, p1);
    std::unordered_map<int, uint64_t> heads{{kFreePageList, head}};
    REQUIRE(unlink_one(mem, db, layout, lists, p1, heads, kFreePageList, &account));
    REQUIRE(*mem.read_u64(color_head + lists.flink) == kKernelListEnd);
    REQUIRE(*mem.read_u64(color_head + lists.blink) == kKernelListEnd);
    REQUIRE((*mem.read_u64(entry(p1) + layout.u1) & kPfnMask) == kKernelListEnd);
    REQUIRE(*mem.read_u64(color_head + lists.total) == 0);
    auto pos = [&](uint64_t addr) {
        for (size_t i = 0; i < mem.writes.size(); ++i) {
            if (mem.writes[i] == addr) return static_cast<int>(i);
        }
        return -1;
    };
    REQUIRE(pos(color_head + lists.total) == 0);
    REQUIRE(pos(color_head + lists.blink) > 0);
    REQUIRE(pos(color_head + lists.flink) > pos(color_head + lists.blink));
}
