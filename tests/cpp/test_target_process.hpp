// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/process.hpp"

#include <string>
#include <vector>

namespace dma_hello {
namespace test {

struct TargetProcessInfo {
    std::string name;
    uint32_t pid;
    uint64_t eprocess;
    uint64_t cr3;
    std::vector<std::pair<uint64_t, uint64_t>> vad_ranges;
    std::vector<std::pair<uint64_t, uint64_t>> phys_ranges;
};

class TargetProcessBuilder {
public:
    TargetProcessInfo build() const;
    
    TargetProcessBuilder& set_name(std::string name);
    TargetProcessBuilder& set_pid(uint32_t pid);
    TargetProcessBuilder& set_cr3(uint64_t cr3);
    TargetProcessBuilder& add_vad_range(uint64_t start, uint64_t end);
    TargetProcessBuilder& add_phys_range(uint64_t pa, uint64_t size);
    
private:
    TargetProcessInfo info_;
};

// Target class that delegates to process_info for integration tests
Target make_target(const TargetProcessInfo& info);

} // namespace test
} // namespace dma_hello
