// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"

#include <cstdint>
#include <string>

namespace dma_hello {

using Target = ProcessInfo;

uint64_t resolve_export(Memory& mem, const Target& target, const std::string& module,
                        const std::string& name);
Target find_process(Memory& mem, const std::string& name);

} // namespace dma_hello
