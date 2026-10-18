// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/mm/vad.hpp"

#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"
#include "dma_hello/mm/constants.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <tuple>
#include <unordered_map>

namespace dma_hello {
namespace {

constexpr uint64_t kUserMin = 0x10000;
constexpr uint64_t kUserMax = 0x00007FFFFFF00000ull;

const std::pair<uint64_t, uint64_t> kForbidden[] = {
    {0x0000000000000000ull, 0x0000000000010000ull},
    {0x000000007FF00000ull, 0x0000000080000000ull},
    {0x00007FFFFFF00000ull, 0x0000800000000000ull},
};

uint64_t node_ptr(uint64_t value) { return value ? (value & ~0x3ull) : 0; }

struct VadLayout {
    int left = 0;
    int right = 8;
    std::optional<int> starting_vpn;
    std::optional<int> ending_vpn;
    std::optional<int> starting_vpn_high;
    std::optional<int> ending_vpn_high;
    std::optional<int> vadroot;
};

VadLayout layout_of(Memory& mem) {
    auto field = [&](std::initializer_list<std::pair<const char*, const char*>> names)
        -> std::optional<int> {
        for (auto [t, f] : names) {
            auto off = mem.field_offset(t, f);
            if (off) return off;
        }
        return std::nullopt;
    };
    VadLayout l;
    l.left = field({{"_RTL_BALANCED_NODE", "Left"}, {"RTL_BALANCED_NODE", "Left"}}).value_or(0);
    l.right = field({{"_RTL_BALANCED_NODE", "Right"}, {"RTL_BALANCED_NODE", "Right"}}).value_or(8);
    l.starting_vpn = field({{"_MMVAD_SHORT", "StartingVpn"},
                            {"MMVAD_SHORT", "StartingVpn"},
                            {"_MMVAD", "StartingVpn"},
                            {"MMVAD", "StartingVpn"}});
    l.ending_vpn = field({{"_MMVAD_SHORT", "EndingVpn"},
                          {"MMVAD_SHORT", "EndingVpn"},
                          {"_MMVAD", "EndingVpn"},
                          {"MMVAD", "EndingVpn"}});
    l.starting_vpn_high = field({{"_MMVAD_SHORT", "StartingVpnHigh"},
                                 {"MMVAD_SHORT", "StartingVpnHigh"},
                                 {"_MMVAD", "StartingVpnHigh"},
                                 {"MMVAD", "StartingVpnHigh"}});
    l.ending_vpn_high = field({{"_MMVAD_SHORT", "EndingVpnHigh"},
                               {"MMVAD_SHORT", "EndingVpnHigh"},
                               {"_MMVAD", "EndingVpnHigh"},
                               {"MMVAD", "EndingVpnHigh"}});
    // 25H2 _MMVAD_SHORT keeps these immediately after the 0x18-byte balanced node.
    if (!l.ending_vpn) {
        LOG_WARN("EndingVpn offset missing; using the 25H2 MMVAD_SHORT fields");
        l.starting_vpn = 0x18;
        l.ending_vpn = 0x1C;
        l.starting_vpn_high = 0x20;
        l.ending_vpn_high = 0x21;
    }
    l.vadroot = field({{"_EPROCESS", "VadRoot"}, {"EPROCESS", "VadRoot"}});
    return l;
}

std::optional<uint64_t> read_vpn(Memory& mem, uint64_t node, std::optional<int> off) {
    if (!off) return std::nullopt;
    auto raw = mem.read_u64(node + *off);
    if (!raw) return std::nullopt;
    return *raw & 0xFFFFFFFFull;
}

void walk(Memory& mem, uint64_t node, const VadLayout& layout,
          std::unordered_map<uint64_t, std::pair<std::optional<uint64_t>, std::optional<uint64_t>>>&
              acc,
          int depth = 0) {
    if (!node || depth > 64 || acc.count(node)) return;
    acc[node] = {std::nullopt, std::nullopt};
    uint64_t left = node_ptr(mem.read_u64(node + layout.left).value_or(0));
    walk(mem, left, layout, acc, depth + 1);
    auto start = read_vpn(mem, node, layout.starting_vpn);
    auto end = read_vpn(mem, node, layout.ending_vpn);
    if (layout.starting_vpn_high && start) {
        auto hs = mem.read_u64(node + *layout.starting_vpn_high);
        if (hs) *start |= (*hs & 0xFF) << 32;
    }
    if (layout.ending_vpn_high && end) {
        auto he = mem.read_u64(node + *layout.ending_vpn_high);
        if (he) *end |= (*he & 0xFF) << 32;
    }
    acc[node] = {start, end};
    uint64_t right = node_ptr(mem.read_u64(node + layout.right).value_or(0));
    walk(mem, right, layout, acc, depth + 1);
}

bool expand_ending_vpn(Memory& mem, uint64_t node, const VadLayout& layout, uint64_t new_end) {
    if (!layout.ending_vpn) return false;
    uint32_t lo = static_cast<uint32_t>(new_end);
    mem.write_kernel(node + *layout.ending_vpn,
                     std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&lo), 4));
    if (layout.ending_vpn_high) {
        uint8_t hi = static_cast<uint8_t>((new_end >> 32) & 0xFF);
        mem.write_kernel(node + *layout.ending_vpn_high, std::span<const uint8_t>(&hi, 1));
    }
    return true;
}

using VadAcc =
    std::unordered_map<uint64_t, std::pair<std::optional<uint64_t>, std::optional<uint64_t>>>;

VadAcc collect_nodes(Memory& mem, const Target& target, const VadLayout& layout, bool log_roots) {
    VadAcc nodes;
    if (!target.eprocess || !layout.vadroot) return nodes;
    int root_off = *layout.vadroot;
    std::vector<uint64_t> candidates;
    candidates.push_back(node_ptr(mem.read_u64(target.eprocess + root_off).value_or(0)));
    uint64_t right =
        node_ptr(mem.read_u64(target.eprocess + root_off + layout.right).value_or(0));
    if (right) candidates.push_back(right);
    std::unordered_map<uint64_t, bool> seen;
    for (uint64_t root : candidates) {
        if (!root || seen[root]) continue;
        seen[root] = true;
        if (log_roots) {
            LOG_INFO("VadRoot candidate: 0x%llx", static_cast<unsigned long long>(root));
        }
        walk(mem, root, layout, nodes);
    }
    return nodes;
}

std::optional<int> field_of(Memory& mem,
                            std::initializer_list<std::pair<const char*, const char*>> names) {
    for (auto [type_name, field] : names) {
        auto off = mem.field_offset(type_name, field);
        if (off) return off;
    }
    return std::nullopt;
}

uint64_t read_counter(Memory& mem, uint64_t addr, const char* what) {
    auto cur = mem.read_u64(addr);
    if (!cur) throw AllocationError(std::string(what) + " is unreadable");
    return *cur;
}

uint64_t add_counter(Memory& mem, uint64_t addr, uint64_t add, const char* what) {
    uint64_t cur = read_counter(mem, addr, what);
    if (add > ~0ull - cur) throw AllocationError(std::string(what) + " would overflow");
    mem.write_u64_kernel(addr, cur + add);
    return cur;
}

void raise_peak(Memory& mem, uint64_t addr, uint64_t now, const char* what) {
    uint64_t peak = read_counter(mem, addr, what);
    if (now > peak) mem.write_u64_kernel(addr, now);
}

uint32_t read_u32(Memory& mem, uint64_t addr, const char* what) {
    auto raw = mem.read(addr, 4);
    if (raw.size() < 4) throw AllocationError(std::string(what) + " is unreadable");
    uint32_t value = 0;
    std::memcpy(&value, raw.data(), 4);
    return value;
}

uint8_t read_u8(Memory& mem, uint64_t addr, const char* what) {
    auto raw = mem.read(addr, 1);
    if (raw.empty()) throw AllocationError(std::string(what) + " is unreadable");
    return raw[0];
}

std::string span_text(uint64_t old_value, uint64_t new_value) {
    char buf[80];
    std::snprintf(buf, sizeof(buf), "%llu->%llu", static_cast<unsigned long long>(old_value),
                  static_cast<unsigned long long>(new_value));
    return buf;
}

uint64_t extend_predecessor(Memory& mem, const Target& target, uint64_t prev_end, uint64_t base_va,
                            uint64_t size, bool commit) {
    auto layout = layout_of(mem);
    if (!target.eprocess || !layout.vadroot) {
        LOG_WARN("EPROCESS.VadRoot offset missing; VAD not extended");
        return 0;
    }
    auto nodes = collect_nodes(mem, target, layout, true);
    uint64_t prev_end_vpn = prev_end >> 12;
    uint64_t end_vpn = (base_va >> 12) + (size / kPageSize) - 1;
    int with_end = 0;
    for (auto& [node, val] : nodes) {
        if (val.second) ++with_end;
    }
    LOG_INFO("VAD walk nodes=%d with EndingVpn=%d want 0x%llx", static_cast<int>(nodes.size()),
             with_end, static_cast<unsigned long long>(prev_end_vpn));
    for (auto& [node, val] : nodes) {
        auto [start, end] = val;
        (void)start;
        if (!end) continue;
        if (*end == prev_end_vpn || (*end + 1) * kPageSize == base_va) {
            if (!commit) {
                LOG_INFO("MMVAD 0x%llx covers the hole and will extend to 0x%llx",
                         static_cast<unsigned long long>(node),
                         static_cast<unsigned long long>(end_vpn));
                return node;
            }
            if (expand_ending_vpn(mem, node, layout, end_vpn)) {
                LOG_INFO("extended MMVAD 0x%llx EndingVpn 0x%llx -> 0x%llx",
                         static_cast<unsigned long long>(node),
                         static_cast<unsigned long long>(*end),
                         static_cast<unsigned long long>(end_vpn));
                return node;
            }
        }
    }
    return 0;
}

std::vector<std::pair<uint64_t, uint64_t>>
gaps(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t size) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    uint64_t cursor = kUserMin;
    for (auto [start, end] : ranges) {
        if (start > cursor) {
            uint64_t hole = (std::min)(start, kUserMax) - cursor;
            if (hole >= size) out.emplace_back(cursor, start - 1);
        }
        cursor = (std::max)(cursor, end + 1);
    }
    if (cursor < kUserMax && (kUserMax - cursor) >= size) out.emplace_back(cursor, kUserMax - 1);
    return out;
}

} // namespace

bool extend_vad_end(Memory& mem, uint64_t node, uint64_t end_vpn) {
    if (!node) return false;
    return expand_ending_vpn(mem, node, layout_of(mem), end_vpn);
}

std::optional<uint64_t> current_vad_end(Memory& mem, uint64_t node) {
    if (!node) return std::nullopt;
    auto layout = layout_of(mem);
    auto end = read_vpn(mem, node, layout.ending_vpn);
    if (!end) return std::nullopt;
    if (layout.ending_vpn_high) {
        auto high = mem.read_u64(node + *layout.ending_vpn_high);
        if (high) *end |= (*high & 0xFF) << 32;
    }
    return end;
}

uint64_t vad_covering(Memory& mem, const Target& target, uint64_t va) {
    auto layout = layout_of(mem);
    if (!target.eprocess || !layout.vadroot) return 0;
    uint64_t vpn = va >> 12;
    for (auto& [node, val] : collect_nodes(mem, target, layout, false)) {
        auto [start, end] = val;
        if (start && end && vpn >= *start && vpn <= *end) return node;
    }
    return 0;
}

void charge_private_commit(Memory& mem, const Target& target, uint64_t vad_node, uint64_t pages,
                           bool grow_virtual) {
    if (pages == 0) return;
    if (pages > (~0ull >> 12)) throw AllocationError("private commit byte count would overflow");
    uint64_t bytes = pages << 12;
    bool any = false;
    std::string vad_s = "skipped";
    std::string proc_s = "skipped";
    std::string quota_s = "skipped";
    std::string sys_s = "skipped";
    std::string virt_s = "skipped";

    auto commit = field_of(mem, {{"_MMVAD_SHORT", "CommitCharge"},
                                 {"MMVAD_SHORT", "CommitCharge"},
                                 {"_MMVAD", "CommitCharge"},
                                 {"MMVAD", "CommitCharge"}});
    auto commit_high = field_of(mem, {{"_MMVAD_SHORT", "CommitChargeHigh"},
                                      {"MMVAD_SHORT", "CommitChargeHigh"},
                                      {"_MMVAD", "CommitChargeHigh"},
                                      {"MMVAD", "CommitChargeHigh"}});
    if (vad_node && commit) {
        uint64_t cur = read_u32(mem, vad_node + *commit, "VAD commit charge");
        if (commit_high) cur |= static_cast<uint64_t>(read_u8(mem, vad_node + *commit_high,
                                                              "VAD commit charge")) << 32;
        if (pages > ~0ull - cur) throw AllocationError("VAD commit charge would overflow");
        uint64_t next = cur + pages;
        uint64_t limit = commit_high ? ((1ull << 40) - 1) : 0xFFFFFFFFull;
        if (next > limit) throw AllocationError("VAD commit charge would overflow");
        uint32_t lo = static_cast<uint32_t>(next);
        mem.write_kernel(vad_node + *commit,
                         std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&lo), 4));
        if (commit_high) {
            uint8_t hi = static_cast<uint8_t>((next >> 32) & 0xFF);
            mem.write_kernel(vad_node + *commit_high, std::span<const uint8_t>(&hi, 1));
        }
        vad_s = span_text(cur, next);
        any = true;
    }

    if (target.eprocess) {
        uint64_t proc = target.eprocess;
        auto proc_commit = field_of(mem, {{"_EPROCESS", "CommitCharge"}, {"EPROCESS", "CommitCharge"}});
        if (proc_commit) {
            uint64_t old = add_counter(mem, proc + *proc_commit, pages, "process commit charge");
            proc_s = span_text(old, old + pages);
            any = true;
            auto peak = field_of(mem, {{"_EPROCESS", "CommitChargePeak"}, {"EPROCESS", "CommitChargePeak"}});
            if (peak) raise_peak(mem, proc + *peak, old + pages, "process commit peak");
        }
        auto private_pages = field_of(mem, {{"_EPROCESS", "NumberOfPrivatePages"},
                                            {"EPROCESS", "NumberOfPrivatePages"}});
        if (private_pages) {
            add_counter(mem, proc + *private_pages, pages, "private page count");
            any = true;
        }
        if (grow_virtual) {
            auto virtual_size = field_of(mem, {{"_EPROCESS", "VirtualSize"}, {"EPROCESS", "VirtualSize"}});
            if (virtual_size) {
                uint64_t old = add_counter(mem, proc + *virtual_size, bytes, "virtual size");
                virt_s = span_text(old, old + bytes);
                any = true;
                auto peak = field_of(mem, {{"_EPROCESS", "PeakVirtualSize"}, {"EPROCESS", "PeakVirtualSize"}});
                if (peak) raise_peak(mem, proc + *peak, old + bytes, "peak virtual size");
            }
        }
        auto quota_block = field_of(mem, {{"_EPROCESS", "QuotaBlock"}, {"EPROCESS", "QuotaBlock"}});
        if (quota_block) {
            uint64_t block = read_counter(mem, proc + *quota_block, "quota block");
            if (block) {
                int stride = mem.type_size("_EPROCESS_QUOTA_ENTRY")
                                 .value_or(mem.type_size("EPROCESS_QUOTA_ENTRY").value_or(0));
                auto usage = field_of(mem, {{"_EPROCESS_QUOTA_ENTRY", "Usage"},
                                            {"EPROCESS_QUOTA_ENTRY", "Usage"}});
                auto peak = field_of(mem, {{"_EPROCESS_QUOTA_ENTRY", "Peak"},
                                           {"EPROCESS_QUOTA_ENTRY", "Peak"}});
                bool fallback = stride <= 0 || !usage || !peak;
                if (stride <= 0) stride = 0x20;
                int usage_off = usage.value_or(0);
                int peak_off = peak.value_or(0x10);
                if (fallback) {
                    LOG_INFO("quota entry stride 0x%x usage+%d peak+%d", stride, usage_off, peak_off);
                }
                // PsPageFile is entry 2. Usage and the process commit are charged
                // together; the quota block counts bytes and the others count pages.
                uint64_t entry = block + static_cast<uint64_t>(stride) * 2;
                uint64_t old = add_counter(mem, entry + usage_off, bytes, "pagefile quota");
                quota_s = span_text(old, old + bytes);
                any = true;
                raise_peak(mem, entry + peak_off, old + bytes, "pagefile quota peak");
            }
        }
        auto job = field_of(mem, {{"_EPROCESS", "CommitChargeJob"}, {"EPROCESS", "CommitChargeJob"}});
        if (job) {
            uint64_t ptr = read_counter(mem, proc + *job, "commit charge job");
            if (ptr) {
                LOG_INFO("CommitChargeJob 0x%llx is set; job commit was left alone",
                         static_cast<unsigned long long>(ptr));
            }
        }
    }

    if (auto symbol = mem.symbol("MmTotalCommittedPages")) {
        if (*symbol) {
            uint64_t old = add_counter(mem, *symbol, pages, "system commit");
            sys_s = span_text(old, old + pages);
            any = true;
        }
    }

    if (!any) {
        LOG_WARN("private pages are uncharged");
        return;
    }
    LOG_INFO("charged %llu private pages vad=%s process=%s quota_bytes=%s system=%s virtual=%s",
             static_cast<unsigned long long>(pages), vad_s.c_str(), proc_s.c_str(), quota_s.c_str(),
             sys_s.c_str(), virt_s.c_str());
}

bool forbidden_range(uint64_t start, uint64_t size) {
    uint64_t end = start + size - 1;
    for (auto [a, b] : kForbidden) {
        if (start < b && end >= a) return true;
    }
    return false;
}

bool adjacent_hole(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, size_t index,
                   uint64_t size, uint64_t& hole_start, uint64_t& prev_start, uint64_t& prev_end) {
    auto [start, end] = ranges[index];
    hole_start = (end + 1 + 0xFFF) & ~0xFFFull;
    uint64_t nxt = (index + 1 < ranges.size()) ? ranges[index + 1].first : kUserMax;
    if (hole_start + size > nxt || hole_start < kUserMin) return false;
    if (forbidden_range(hole_start, size)) return false;
    if (start >= 0x7FF00000ull && start < 0x80000000ull) return false;
    prev_start = start;
    prev_end = end;
    return true;
}

std::optional<std::tuple<uint64_t, uint64_t, uint64_t>>
prefer_adjacent(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t size) {
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t hole = 0, start = 0, end = 0;
        if (!adjacent_hole(ranges, i, size, hole, start, end)) continue;
        return std::make_tuple(hole, start, end);
    }
    return std::nullopt;
}

std::vector<VadCandidate> vad_candidates(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                        uint64_t size) {
    std::vector<VadCandidate> out;
    std::vector<uint64_t> adjacent_bases;
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t hole = 0, start = 0, end = 0;
        if (!adjacent_hole(ranges, i, size, hole, start, end)) continue;
        out.push_back(VadCandidate{hole, start, end, true});
        adjacent_bases.push_back(hole);
    }
    for (auto [hole_lo, hole_hi] : gaps(ranges, size)) {
        uint64_t aligned = (hole_lo + 0xFFF) & ~0xFFFull;
        if (aligned + size - 1 > hole_hi || forbidden_range(aligned, size)) continue;
        bool repeated = false;
        for (uint64_t base : adjacent_bases) {
            if (base == aligned) repeated = true;
        }
        if (repeated) continue;
        out.push_back(VadCandidate{aligned, 0, 0, false});
    }
    return out;
}

std::optional<VadSpan> plan_candidate(Memory& mem, const Target& target,
                                     const VadCandidate& candidate, uint64_t size) {
    if (!candidate.adjacent) return std::nullopt;
    uint64_t node = extend_predecessor(mem, target, candidate.prev_end, candidate.base_va, size,
                                      false);
    if (!node) return std::nullopt;
    return VadSpan{candidate.base_va, size, node, true};
}

std::optional<uint64_t> first_gap(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                  uint64_t size) {
    for (auto [hole_lo, hole_hi] : gaps(ranges, size)) {
        uint64_t aligned = (hole_lo + 0xFFF) & ~0xFFFull;
        if (aligned + size - 1 <= hole_hi && !forbidden_range(aligned, size)) {
            LOG_INFO("non-adjacent hole at 0x%llx", static_cast<unsigned long long>(aligned));
            return aligned;
        }
    }
    return std::nullopt;
}

VadSpan choose_and_extend(Memory& mem, const Target& target, const ClaimedPages& pages,
                         bool commit) {
    uint64_t size = pages.page_count * kPageSize;
    auto ranges = mem.vad_map(target.pid);
    LOG_INFO("existing VAD entries: %d", static_cast<int>(ranges.size()));
    std::sort(ranges.begin(), ranges.end());

    auto adj = prefer_adjacent(ranges, size);
    if (!adj) throw AllocationError("no adjacent VAD can cover the range");
    auto [base_va, prev_start, prev_end] = *adj;
    LOG_INFO("hole after 0x%llx-0x%llx -> 0x%llx", static_cast<unsigned long long>(prev_start),
             static_cast<unsigned long long>(prev_end), static_cast<unsigned long long>(base_va));
    uint64_t node = extend_predecessor(mem, target, prev_end, base_va, size, commit);
    if (!node) {
        throw AllocationError(
            "adjacent VAD could not be extended; refusing to program PTEs with no covering node");
    }
    return VadSpan{base_va, size, node, true};
}

} // namespace dma_hello
