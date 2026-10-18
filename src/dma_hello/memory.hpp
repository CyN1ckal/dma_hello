// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace dma_hello {

struct ProcessInfo {
    std::string name;
    uint32_t pid = 0;
    uint64_t eprocess = 0;
    uint64_t cr3 = 0;
};

class Memory {
public:
    virtual ~Memory() = default;

    virtual std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                                      uint32_t pid = 0) = 0;
    virtual void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
                       uint32_t pid = 0) = 0;

    virtual std::optional<uint64_t> virt2phys(uint64_t va, uint32_t pid = 0) {
        (void)va;
        (void)pid;
        return std::nullopt;
    }
    virtual std::optional<uint64_t> symbol(const char* name) {
        (void)name;
        return std::nullopt;
    }
    virtual std::optional<int> type_size(const char* type) {
        (void)type;
        return std::nullopt;
    }
    virtual std::optional<int> field_offset(const char* type, const char* field) {
        (void)type;
        (void)field;
        return std::nullopt;
    }
    virtual uint32_t kernel_pid() const { return 0; }

    virtual ProcessInfo find_process(const std::string& name) {
        (void)name;
        throw SessionError("find_process requires a live MemProcFS session");
    }
    virtual uint64_t export_addr(uint32_t pid, const std::string& module, const std::string& name) {
        (void)pid;
        (void)module;
        (void)name;
        throw SessionError("export_addr requires a live MemProcFS session");
    }
    virtual std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t pid) {
        (void)pid;
        return {};
    }
    virtual std::vector<std::pair<uint64_t, uint64_t>> phys_map() { return {}; }
    virtual std::unordered_map<uint64_t, std::string> pfn_types(const std::vector<uint64_t>& pfns) {
        (void)pfns;
        return {};
    }

    std::optional<uint64_t> read_u64(uint64_t address, bool physical = false, uint32_t pid = 0);
    void write_u64(uint64_t address, uint64_t value, bool physical = false, uint32_t pid = 0);
    virtual void write_kernel(uint64_t address, std::span<const uint8_t> data);
    virtual void write_u64_kernel(uint64_t address, uint64_t value);
};

} // namespace dma_hello
