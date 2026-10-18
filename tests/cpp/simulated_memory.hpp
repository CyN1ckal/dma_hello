// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/mm/constants.hpp"
#include "test_target_process.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace dma_hello {
namespace test {

// Sparse stand-in for a MemProcFS session. Pages are 4 KiB and keyed by
// page base so kernel virtual addresses never index a single vector.
class SimulatedMemory : public Memory {
public:
    explicit SimulatedMemory(const TargetProcessInfo& target_info);

    std::vector<uint8_t> read(uint64_t address, size_t size, bool physical = false,
                              uint32_t pid = 0) override;
    void write(uint64_t address, std::span<const uint8_t> data, bool physical = false,
               uint32_t pid = 0) override;

    std::optional<uint64_t> virt2phys(uint64_t va, uint32_t pid = 0) override;
    std::optional<uint64_t> symbol(const char* name) override;
    std::optional<int> type_size(const char* type) override;
    std::optional<int> field_offset(const char* type, const char* field) override;
    uint32_t kernel_pid() const override { return kKernelPid; }

    ProcessInfo find_process(const std::string& name) override;
    uint64_t export_addr(uint32_t pid, const std::string& module,
                         const std::string& name) override;
    std::vector<std::pair<uint64_t, uint64_t>> vad_map(uint32_t pid) override;
    std::vector<std::pair<uint64_t, uint64_t>> phys_map() override;
    std::unordered_map<uint64_t, std::string> pfn_types(
        const std::vector<uint64_t>& pfns) override;

    void write_with_verify(uint64_t address, std::span<const uint8_t> data,
                           bool physical = false, uint32_t pid = 0);

    // The next n write() calls succeed. The following write() throws
    // SessionError("dma glitch"), then writes succeed again. n == 0 throws
    // on the next write. Default is to never throw.
    void fail_write_after(int n);

    void clear_symbol(const std::string& name);
    void set_symbol(const std::string& name, uint64_t value);
    void set_type_size(const std::string& type, int size);
    void set_field_offset(const std::string& type, const std::string& field, int offset);
    void map_va(uint64_t va, uint64_t pa);
    void set_pfn_type(uint64_t pfn, std::string type);
    void add_vad_range(uint64_t start, uint64_t end);

    const std::unordered_map<std::string, uint64_t>& get_symbols() const { return symbols_; }
    const std::unordered_map<std::string, int>& get_type_sizes() const { return type_sizes_; }
    const std::unordered_map<std::string, std::unordered_map<std::string, int>>&
        get_field_offsets() const { return field_offsets_; }

private:
    std::vector<uint8_t>& ensure_page(uint64_t address);
    // Page-table translation for this target's CR3. Empty when the VA is not
    // present, in which case the sparse map is the kernel store.
    std::vector<std::pair<uint64_t, size_t>> translate(uint64_t address, size_t size);

    TargetProcessInfo target_info_;
    std::unordered_map<uint64_t, std::vector<uint8_t>> pages_;
    std::unordered_map<uint64_t, uint64_t> va_to_pa_;
    std::unordered_map<std::string, uint64_t> symbols_;
    std::unordered_map<std::string, int> type_sizes_;
    std::unordered_map<std::string, std::unordered_map<std::string, int>> field_offsets_;
    std::unordered_map<uint64_t, std::string> pfn_type_;
    ProcessInfo planted_;
    int writes_before_fail_ = -1;

    static constexpr uint32_t kKernelPid = 4;
};

} // namespace test
} // namespace dma_hello
