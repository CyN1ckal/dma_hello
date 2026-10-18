// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/hook.hpp"
#include "dma_hello/memory.hpp"
#include "dma_hello/process.hpp"

#include <cstdint>

namespace dma_hello {

Allocation allocate(Memory& mem, const Target& target, uint64_t size, uint32_t protection);

} // namespace dma_hello
