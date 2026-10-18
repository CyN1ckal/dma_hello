// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/config.hpp"
#include "dma_hello/hook.hpp"
#include "dma_hello/pe.hpp"
#include "dma_hello/process.hpp"

namespace dma_hello {

struct InjectResult {
    Target target;
    Allocation allocation;
    PeImage pe;
    Hook hook;
};

InjectResult run(const Settings& settings);

} // namespace dma_hello
