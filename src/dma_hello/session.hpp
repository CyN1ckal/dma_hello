// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

struct tdVMM_HANDLE;
typedef struct tdVMM_HANDLE* VMM_HANDLE;

namespace dma_hello {

class Session final : public Memory {
public:
    explicit Session(const std::string& device);
    ~Session() override;

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                              uint32_t pid = 0) override;
    void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
               uint32_t pid = 0) override;
    std::optional<uint64_t> virt2phys(uint64_t va, uint32_t pid = 0) override;
    std::optional<uint64_t> symbol(const char* name) override;
    std::optional<int> type_size(const char* type) override;
    std::optional<int> field_offset(const char* type, const char* field) override;
    uint32_t kernel_pid() const override { return kernel_pid_; }

    ProcessInfo find_process(const std::string& name) override;
    uint64_t export_addr(uint32_t pid, const std::string& module,
                         const std::string& name) override;
    std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t pid) override;
    std::vector<std::pair<uint64_t, uint64_t>> phys_map() override;
    std::unordered_map<uint64_t, std::string> pfn_types(const std::vector<uint64_t>& pfns) override;

private:
    uint32_t resolve_pid(bool physical, uint32_t pid) const;
    void ensure_kernel_symbols();

    VMM_HANDLE handle_ = nullptr;
    uint32_t kernel_pid_ = 4;
    bool kernel_symbols_checked_ = false;
    std::unordered_map<std::string, std::optional<uint64_t>> symbol_cache_;
    std::unordered_map<std::string, std::optional<int>> size_cache_;
    std::unordered_map<std::string, std::optional<int>> field_cache_;
};

} // namespace dma_hello
