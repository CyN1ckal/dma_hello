// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/process.hpp"

namespace dma_hello {

Target find_process(Memory& mem, const std::string& name) { return mem.find_process(name); }

uint64_t resolve_export(Memory& mem, const Target& target, const std::string& module,
                        const std::string& name) {
    return mem.export_addr(target.pid, module, name);
}

} // namespace dma_hello
