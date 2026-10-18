// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "simulated_memory.hpp"

#include "dma_hello/error.hpp"
#include "dma_hello/mm/page_tables.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace dma_hello {
namespace test {
namespace {

std::string lower_copy(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

const std::unordered_map<std::string, uint64_t>& common_exports() {
    static const std::unordered_map<std::string, uint64_t> table = {
        {"user32.dll!peekmessagew", 0x7FF812345678ull},
        {"user32.dll!messageboxa", 0x7FF812345ABCull},
        {"user32.dll!messageboxw", 0x7FF812345CDEull},
        {"kernel32.dll!gettickcount", 0x7FF812346000ull},
        {"kernel32.dll!gettickcount64", 0x7FF812346010ull},
        {"kernel32.dll!rtlfreeheap", 0x7FF812346020ull},
        {"kernel32.dll!freememory", 0x7FF812346030ull},
        {"ntdll.dll!ntwritevirtualmemory", 0x7FF812346040ull},
    };
    return table;
}

} // namespace

SimulatedMemory::SimulatedMemory(const TargetProcessInfo& target_info)
    : target_info_(target_info) {
    planted_.name = target_info_.name;
    planted_.pid = target_info_.pid;
    planted_.eprocess = target_info_.eprocess;
    planted_.cr3 = target_info_.cr3;

    symbols_ = {
        {"MmPfnDatabase", 0xFFFFFA8000000000ull},
        {"MmPteBase", kDefaultPteBase},
        {"MiSystemPartition", 0xFFFFFA8000001000ull},
        {"MmZeroedPageListHead", 0xFFFFFA8000002000ull},
        {"MmFreePageListHead", 0xFFFFFA8000003000ull},
        {"MiZeroedPageListHead", 0xFFFFFA8000002000ull},
        {"MiFreePageListHead", 0xFFFFFA8000003000ull},
    };

    type_sizes_ = {
        {"MMPFN", 0x30},
        {"MMPFNLIST", 0x28},
        {"_MMPFNLIST", 0x28},
        {"RTL_BALANCED_NODE", 0x18},
        {"MMVAD_SHORT", 0x40},
        {"MMVAD", 0x50},
        {"_EPROCESS", 0x580},
        {"MI_PARTITION", 0x800},
    };

    field_offsets_ = {
        {"MMPFN", {
            {"u1", 0},
            {"PteAddress", 8},
            {"u2", 0x18},
            {"u3", 0x20},
            {"u4", 0x28},
            {"OriginalPte", 0x10},
        }},
        {"MMPFNLIST", {
            {"Total", 0},
            {"Flink", 0x10},
            {"Blink", 0x18},
        }},
        {"_MMPFNLIST", {
            {"Total", 0},
            {"Flink", 0x10},
            {"Blink", 0x18},
        }},
        {"RTL_BALANCED_NODE", {
            {"Left", 0},
            {"Right", 8},
        }},
        {"MMVAD_SHORT", {
            {"StartingVpn", 0x8},
            {"EndingVpn", 0xC},
            {"StartingVpnHigh", 0x10},
            {"EndingVpnHigh", 0x14},
        }},
        {"MMVAD", {
            {"StartingVpn", 0x8},
            {"EndingVpn", 0xC},
            {"StartingVpnHigh", 0x10},
            {"EndingVpnHigh", 0x14},
        }},
        {"_EPROCESS", {
            {"VadRoot", 0x38},
        }},
    };
    write_u64(kDefaultPteBase, kDefaultPteBase);
}

std::vector<uint8_t>& SimulatedMemory::ensure_page(uint64_t address) {
    const uint64_t key = address & ~0xFFFull;
    auto it = pages_.find(key);
    if (it == pages_.end()) {
        it = pages_.emplace(key, std::vector<uint8_t>(static_cast<size_t>(kPageSize), 0)).first;
    }
    return it->second;
}

std::vector<std::pair<uint64_t, size_t>> SimulatedMemory::translate(uint64_t address,
                                                                         size_t size) {
    std::vector<std::pair<uint64_t, size_t>> parts;
    if (!target_info_.cr3 || size == 0) return parts;
    try {
        size_t off = 0;
        while (off < size) {
            const uint64_t addr = address + static_cast<uint64_t>(off);
            const size_t n = (std::min)(size - off, static_cast<size_t>(kPageSize - (addr & 0xFFF)));
            parts.emplace_back(virt_to_phys(*this, target_info_.cr3, addr), n);
            off += n;
        }
    } catch (const MappingError&) {
        parts.clear();
    }
    return parts;
}

std::vector<uint8_t> SimulatedMemory::read(uint64_t address, size_t size, bool physical,
                                           uint32_t pid) {
    (void)pid;
    if (!physical) {
        auto parts = translate(address, size);
        if (!parts.empty()) {
            std::vector<uint8_t> buf;
            buf.reserve(size);
            for (auto [pa, n] : parts) {
                auto chunk = read(pa, n, true, pid);
                buf.insert(buf.end(), chunk.begin(), chunk.end());
            }
            return buf;
        }
    }
    std::vector<uint8_t> buf(size, 0);
    for (size_t i = 0; i < size; ++i) {
        const uint64_t at = address + static_cast<uint64_t>(i);
        auto it = pages_.find(at & ~0xFFFull);
        if (it == pages_.end()) continue;
        buf[i] = it->second[static_cast<size_t>(at & 0xFFF)];
    }
    return buf;
}

void SimulatedMemory::write(uint64_t address, std::span<const uint8_t> data, bool physical,
                            uint32_t pid) {
    (void)pid;
    if (!physical) {
        auto parts = translate(address, data.size());
        if (!parts.empty()) {
            size_t off = 0;
            for (auto [pa, n] : parts) {
                write(pa, data.subspan(off, n), true, pid);
                off += n;
            }
            return;
        }
    }
    if (writes_before_fail_ == 0) {
        writes_before_fail_ = -1;
        throw SessionError("dma glitch");
    }
    if (writes_before_fail_ > 0) --writes_before_fail_;

    for (size_t i = 0; i < data.size(); ++i) {
        const uint64_t at = address + static_cast<uint64_t>(i);
        ensure_page(at)[static_cast<size_t>(at & 0xFFF)] = data[i];
    }
}

void SimulatedMemory::write_with_verify(uint64_t address, std::span<const uint8_t> data,
                                        bool physical, uint32_t pid) {
    write(address, data, physical, pid);
    auto back = read(address, data.size(), physical, pid);
    if (back.size() != data.size() ||
        !std::equal(back.begin(), back.end(), data.begin())) {
        throw SessionError("write verification failed");
    }
}

void SimulatedMemory::fail_write_after(int n) { writes_before_fail_ = n; }

void SimulatedMemory::clear_symbol(const std::string& name) { symbols_.erase(name); }

void SimulatedMemory::set_symbol(const std::string& name, uint64_t value) { symbols_[name] = value; }

void SimulatedMemory::set_type_size(const std::string& type, int size) { type_sizes_[type] = size; }

void SimulatedMemory::set_field_offset(const std::string& type, const std::string& field,
                                       int offset) {
    field_offsets_[type][field] = offset;
}

void SimulatedMemory::add_vad_range(uint64_t start, uint64_t end) {
    target_info_.vad_ranges.emplace_back(start, end);
}

void SimulatedMemory::map_va(uint64_t va, uint64_t pa) {
    va_to_pa_[va & ~0xFFFull] = pa & ~0xFFFull;
}

void SimulatedMemory::set_pfn_type(uint64_t pfn, std::string type) {
    pfn_type_[pfn] = std::move(type);
}

std::optional<uint64_t> SimulatedMemory::virt2phys(uint64_t va, uint32_t pid) {
    (void)pid;
    auto it = va_to_pa_.find(va & ~0xFFFull);
    if (it == va_to_pa_.end()) return std::nullopt;
    return it->second | (va & 0xFFF);
}

std::optional<uint64_t> SimulatedMemory::symbol(const char* name) {
    auto it = symbols_.find(name ? name : "");
    if (it == symbols_.end()) return std::nullopt;
    return it->second;
}

std::optional<int> SimulatedMemory::type_size(const char* type) {
    auto it = type_sizes_.find(type ? type : "");
    if (it == type_sizes_.end()) return std::nullopt;
    return it->second;
}

std::optional<int> SimulatedMemory::field_offset(const char* type, const char* field) {
    auto type_it = field_offsets_.find(type ? type : "");
    if (type_it == field_offsets_.end()) return std::nullopt;
    auto field_it = type_it->second.find(field ? field : "");
    if (field_it == type_it->second.end()) return std::nullopt;
    return field_it->second;
}

ProcessInfo SimulatedMemory::find_process(const std::string& name) {
    if (planted_.name == name) return planted_;
    throw ProcessNotFound(name + " is not running on the target");
}

uint64_t SimulatedMemory::export_addr(uint32_t pid, const std::string& module,
                                      const std::string& name) {
    (void)pid;
    const std::string key = lower_copy(module) + "!" + lower_copy(name);
    auto it = common_exports().find(key);
    if (it == common_exports().end()) {
        throw SessionError("export not found: " + module + "!" + name);
    }
    return it->second;
}

std::vector<std::pair<uint64_t, uint64_t>> SimulatedMemory::vad_map(uint32_t pid) {
    std::vector<std::pair<uint64_t, uint64_t>> result;
    if (pid != target_info_.pid) return result;
    result = target_info_.vad_ranges;
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::pair<uint64_t, uint64_t>> SimulatedMemory::phys_map() {
    std::vector<std::pair<uint64_t, uint64_t>> result;
    result.reserve(target_info_.phys_ranges.size());
    for (const auto& [start, end] : target_info_.phys_ranges) {
        const uint64_t size = end - start + 1;
        result.emplace_back(start, size);
    }
    return result;
}

std::unordered_map<uint64_t, std::string> SimulatedMemory::pfn_types(
    const std::vector<uint64_t>& pfns) {
    std::optional<uint64_t> db;
    auto ptr = symbol("MmPfnDatabase");
    if (ptr) {
        auto value = read_u64(*ptr);
        if (value && *value > 0xFFFF800000000000ull) db = *value;
    }
    const int mmpfn = type_size("MMPFN").value_or(0x30);
    const int u3 = field_offset("MMPFN", "u3").value_or(0x20);
    std::unordered_map<uint64_t, std::string> result;
    for (uint64_t pfn : pfns) {
        auto it = pfn_type_.find(pfn);
        if (it != pfn_type_.end()) {
            result[pfn] = it->second;
            continue;
        }
        // No database entry is the zeroed list. ActiveAndValid is what
        // mark_pfn_active stores, and MemProcFS then reports the frame as
        // neither Zeroed nor Free. Claimed slack is marked Active before
        // the next unlink, so a later scan does not treat it as a list node.
        int loc = 0;
        if (db) {
            auto e1 = read(*db + pfn * static_cast<uint64_t>(mmpfn) +
                               static_cast<uint64_t>(u3) + 2,
                           1);
            if (!e1.empty()) loc = e1[0] & 0x07;
        }
        if (loc == kZeroedPageList) result[pfn] = "Zeroed";
        else if (loc == kFreePageList) result[pfn] = "Free";
        else result[pfn] = "Other";
    }
    return result;
}

} // namespace test
} // namespace dma_hello
