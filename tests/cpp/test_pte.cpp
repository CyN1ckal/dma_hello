// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/mm/page_tables.hpp"

using namespace dma_hello;

TEST_CASE("encode rwx pte") {
    auto pte = encode_pte(0x12345, 0x40);
    REQUIRE(pte & kPteP);
    REQUIRE(pte & kPteRw);
    REQUIRE(pte & kPteUs);
    REQUIRE_FALSE(pte & kPteNx);
    REQUIRE(((pte >> 12) & ((1ull << 40) - 1)) == 0x12345);
}

TEST_CASE("encode readonly pte") {
    auto pte = encode_pte(1, 0x02);
    REQUIRE(pte & kPteP);
    REQUIRE_FALSE(pte & kPteRw);
    REQUIRE(pte & kPteNx);
}

TEST_CASE("nx matrix") {
    for (uint32_t prot : {0x40u, 0x20u, 0x10u}) REQUIRE_FALSE(encode_pte(1, prot) & kPteNx);
    for (uint32_t prot : {0x02u, 0x04u, 0u}) REQUIRE(encode_pte(1, prot) & kPteNx);
    REQUIRE_THROWS_AS(encode_pte(1ull << 40, 0x40), MappingError);
}
