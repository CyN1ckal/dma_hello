// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "test_target_process.hpp"

namespace dma_hello {
namespace test {

TargetProcessBuilder& TargetProcessBuilder::set_name(std::string name) {
    info_.name = std::move(name);
    return *this;
}

TargetProcessBuilder& TargetProcessBuilder::set_pid(uint32_t pid) {
    info_.pid = pid;
    return *this;
}

TargetProcessBuilder& TargetProcessBuilder::set_cr3(uint64_t cr3) {
    info_.cr3 = cr3;
    return *this;
}

TargetProcessBuilder& TargetProcessBuilder::add_vad_range(uint64_t start, uint64_t end) {
    info_.vad_ranges.emplace_back(start, end);
    return *this;
}

TargetProcessBuilder& TargetProcessBuilder::add_phys_range(uint64_t pa, uint64_t size) {
    info_.phys_ranges.emplace_back(pa, pa + size - 1);
    return *this;
}

TargetProcessInfo TargetProcessBuilder::build() const {
    TargetProcessInfo result = info_;
    if (result.name.empty()) result.name = "notepad.exe";
    if (result.pid == 0) result.pid = 0x1234;
    if (result.cr3 == 0) result.cr3 = 0x1A2F3C000;
    if (result.eprocess == 0) result.eprocess = 0xFFFF800000000000ull + result.pid;
    return result;
}

Target make_target(const TargetProcessInfo& info) {
    Target t;
    t.name = info.name;
    t.pid = info.pid;
    t.eprocess = info.eprocess;
    t.cr3 = info.cr3;
    return t;
}

} // namespace test
} // namespace dma_hello
