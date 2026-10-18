// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"

// These names stay in the binary so a [system] filter has somewhere to land.
// They do not open a device. Live injection is a manual run of dma_hello.exe.
TEST_CASE("fpga smoke is opt-in", "[system]") {
    SKIP("live injection is manual; this case does not open a device");
}

TEST_CASE("fpga multi-process is opt-in", "[system]") {
    SKIP("live injection is manual; this case does not open a device");
}

TEST_CASE("fpga stress is opt-in", "[system]") {
    SKIP("live injection is manual; this case does not open a device");
}
