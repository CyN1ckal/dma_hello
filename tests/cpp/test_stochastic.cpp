// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "world.hpp"

using namespace dma_hello;
using namespace dma_hello::test;

namespace {

class StickyGlitch : public SimulatedMemory {
public:
    using SimulatedMemory::SimulatedMemory;
    bool armed = false;
    int budget = 0;

    void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
               uint32_t pid = 0) override {
        if (armed) {
            if (budget <= 0) throw SessionError("dma glitch");
            --budget;
        }
        SimulatedMemory::write(address, data, physical, pid);
    }
};

} // namespace

TEST_CASE("seeded write glitches leave the free list well formed", "[stress]") {
    LogSilence quiet;
    constexpr int kPfns = 200;
    constexpr int kTrials = 24;
    int survived = 0;
    for (int n = 0; n < kTrials; ++n) {
        StickyGlitch mem(make_info(kPfns));
        plant_free_list(mem, kPfns);
        auto before = mem.read_u64(kListHead).value_or(0);
        bool claimed = false;
        int table_count = -1;
        try {
            if (n % 2 == 0) {
                mem.fail_write_after(n % 11);
            } else {
                mem.armed = true;
                mem.budget = n % 5;
            }
            auto pages = allocate_physical_pages(mem, 0x1000);
            claimed = pages.frames.size() == 1;
            table_count = static_cast<int>(pages.table_frames.size());
        } catch (const PfnRollbackError&) {
            claimed = false;
        } catch (const PfnError&) {
            claimed = false;
        }
        auto total = mem.read_u64(kListHead);
        auto flink = mem.read_u64(kListHead + 0x10);
        auto blink = mem.read_u64(kListHead + 0x18);
        REQUIRE(total);
        REQUIRE(flink);
        REQUIRE(blink);
        REQUIRE(*total <= before);
        REQUIRE(list_pfn_or_end(*flink, kPfns));
        REQUIRE(list_pfn_or_end(*blink, kPfns));
        if (claimed) {
            ++survived;
            // A write budget can run out after a few good unlinks. The claim
            // then returns the pages it actually took. Total has to match that
            // count, and the chain has to be that long.
            uint64_t taken = static_cast<uint64_t>(1 + table_count);
            REQUIRE(*total == before - taken);
            uint64_t cursor = *flink & kPfnMask;
            int seen = 0;
            while (cursor != kPfnTerminator && seen <= kPfns) {
                REQUIRE(list_pfn_or_end(cursor, kPfns));
                auto next = mem.read_u64(kDb + cursor * kMmpfn);
                REQUIRE(next);
                cursor = *next & kPfnMask;
                ++seen;
            }
            REQUIRE(seen == static_cast<int>(*total));
        }
    }
    REQUIRE(survived > 0);
    REQUIRE(survived < kTrials);
}
