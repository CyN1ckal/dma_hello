// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/mm/pfn.hpp"

#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <string>
#include <thread>
#include <unordered_set>

namespace dma_hello {
namespace {

uint64_t flink(uint64_t u1) { return u1 & kPfnMask; }
uint64_t blink(uint64_t u2) { return u2 & kPfnMask; }

std::optional<int> page_location(Memory& mem, uint64_t db, const MmpfnLayout& layout,
                                 uint64_t pfn) {
    uint64_t va = db + pfn * layout.size + layout.u3 + 2;
    auto e1 = mem.read(va, 1);
    if (e1.empty()) return std::nullopt;
    return e1[0] & 0x07;
}

// Link qwords carry node and lock bits above the 40-bit PFN. Total is the
// live list counter and is compared in full, with a small further decrement
// accepted when the zero-page thread races the claim.
struct PfnQword {
    uint64_t addr = 0;
    uint64_t value = 0;
    uint64_t mask = ~uint64_t{0};
    bool total = false;
};

struct Backup {
    PfnQword op;
    uint64_t old_value = 0;
};

std::string hex_qword(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return buf;
}

constexpr uint64_t kTotalSettle = 8;
// MiReplenishPageSlist runs at DISPATCH_LEVEL. A walker that already sampled
// this color's Total finishes in microseconds. A DMA store takes milliseconds,
// so this wait lets that walker lock the old tail before Flink changes.
constexpr auto kColorReplenishWait = std::chrono::milliseconds(5);

bool total_landed(uint64_t now, uint64_t written) {
    if (now == written) return true;
    return now < written && written - now <= kTotalSettle;
}

bool qword_landed(uint64_t now, const PfnQword& op) {
    if (op.total) return total_landed(now, op.value);
    return (now & op.mask) == (op.value & op.mask);
}

bool still_snapshot(uint64_t now, uint64_t old_value, const PfnQword& op) {
    if (op.total) return now == old_value;
    return (now & op.mask) == (old_value & op.mask);
}

struct Probe {
    bool landed = false;
    bool readable = false;
    uint64_t value = 0;
};

Probe wait_landed(Memory& mem, const PfnQword& op, bool physical, uint64_t addr) {
    Probe probe;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::optional<uint64_t> now =
            physical ? mem.read_u64(addr, true, 0) : mem.read_u64(addr);
        if (now) {
            probe.readable = true;
            probe.value = *now;
            if (qword_landed(*now, op)) {
                probe.landed = true;
                return probe;
            }
        }
        if (attempt + 1 < 8) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return probe;
}

std::string verify_text(const PfnQword& op, uint64_t old_value, const Probe& probe,
                        std::optional<uint64_t> pa) {
    std::string text = "physical write verify failed va=" + hex_qword(op.addr);
    text += " pa=" + (pa ? hex_qword(*pa) : std::string("none"));
    text += " mask=" + hex_qword(op.mask);
    text += " want=" + hex_qword(op.value);
    text += " old=" + hex_qword(old_value);
    text += " got=" + (probe.readable ? hex_qword(probe.value) : std::string("unreadable"));
    return text;
}

void write_fresh_total(Memory& mem, uint64_t addr, uint64_t* published);

void write_pfn_qword(Memory& mem, const PfnQword& op, uint64_t old_value) {
    uint8_t raw[8];
    store_le(raw, op.value);
    auto bytes = std::span<const uint8_t>(raw, 8);
    bool api_rejected = false;
    try {
        mem.write(op.addr, bytes, false, mem.kernel_pid());
    } catch (const SessionError& e) {
        if (std::string(e.what()) != "write failed") throw;
        api_rejected = true;
    }
    if (!api_rejected) {
        auto probe = wait_landed(mem, op, false, op.addr);
        if (probe.landed) return;
        // The qword is no longer the snapshot, so the kernel moved it after
        // the write. Another write would splice over that newer link.
        if (!(probe.readable && still_snapshot(probe.value, old_value, op))) {
            auto text = verify_text(op, old_value, probe, std::nullopt);
            LOG_ERROR("%s", text.c_str());
            throw SessionError(text);
        }
    }
    auto pa = mem.virt2phys(op.addr, mem.kernel_pid());
    if (!pa) throw SessionError("kernel VA is not mapped and has no physical translation");
    mem.write(*pa, bytes, true, 0);
    auto probe = wait_landed(mem, op, true, *pa);
    if (probe.landed) return;
    auto text = verify_text(op, old_value, probe, pa);
    LOG_ERROR("%s", text.c_str());
    throw SessionError(text);
}

void restore_u64s(Memory& mem, const std::vector<Backup>& backups) {
    for (auto it = backups.rbegin(); it != backups.rend(); ++it) {
        const Backup& saved = *it;
        try {
            auto now = mem.read_u64(saved.op.addr);
            if (!now) {
                throw PfnRollbackError("PFN unlink rollback could not read " +
                                       hex_qword(saved.op.addr));
            }
            if (saved.op.total) {
                if (*now == saved.old_value) continue;
                uint64_t span = *now > saved.old_value ? *now - saved.old_value
                                                      : saved.old_value - *now;
                if (*now != saved.op.value || span > kTotalSettle + 1) {
                    LOG_ERROR("pfn total %s moved old=%s wrote=%s now=%s; leaving it",
                              hex_qword(saved.op.addr).c_str(), hex_qword(saved.old_value).c_str(),
                              hex_qword(saved.op.value).c_str(), hex_qword(*now).c_str());
                    continue;
                }
            } else if (still_snapshot(*now, saved.old_value, saved.op)) {
                continue;
            } else if (!qword_landed(*now, saved.op)) {
                throw PfnRollbackError(
                    "PFN unlink rollback left a replaced qword at " + hex_qword(saved.op.addr) +
                    " old=" + hex_qword(saved.old_value) + " wrote=" + hex_qword(saved.op.value) +
                    " now=" + hex_qword(*now));
            }
            PfnQword back = saved.op;
            back.value = saved.old_value;
            back.total = false;
            write_pfn_qword(mem, back, *now);
        } catch (const PfnRollbackError&) {
            throw;
        } catch (const std::exception& e) {
            throw PfnRollbackError("PFN unlink rollback failed at " + hex_qword(saved.op.addr) +
                                   " old=" + hex_qword(saved.old_value) +
                                   " wrote=" + hex_qword(saved.op.value) + ": " + e.what());
        }
    }
}

std::vector<Backup> write_u64s(Memory& mem, const std::vector<PfnQword>& ops,
                              const std::function<void()>& verify_neighbors) {
    std::vector<Backup> backups;
    try {
        for (const auto& op : ops) {
            auto old = mem.read_u64(op.addr);
            if (!old) throw PfnError("short read before unlink write");
            Backup saved{op, *old};
            if (op.total) {
                uint64_t published = *old;
                try {
                    write_fresh_total(mem, op.addr, &published);
                    saved.op.value = published;
                    backups.push_back(saved);
                } catch (...) {
                    saved.op.value = published;
                    backups.push_back(saved);
                    throw;
                }
            } else {
                backups.push_back(saved);
                write_pfn_qword(mem, op, *old);
            }
        }
        if (verify_neighbors) verify_neighbors();
    } catch (const PfnRollbackError&) {
        throw;
    } catch (...) {
        restore_u64s(mem, backups);
        throw;
    }
    return backups;
}

uint64_t read_total(Memory& mem, uint64_t addr) {
    auto value = mem.read_u64(addr);
    if (!value) throw SessionError("list total unreadable");
    return *value;
}

// Publish live-1, never a count captured before the link edits. The zero-page
// thread drops this counter by thousands of pages during a slow DMA claim, and
// writing the older number raises Total. That is a PFN_LIST_CORRUPT.
void write_fresh_total(Memory& mem, uint64_t addr, uint64_t* published) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        uint64_t first = read_total(mem, addr);
        uint64_t second = read_total(mem, addr);
        uint64_t high = first > second ? first : second;
        uint64_t low = first < second ? first : second;
        if (high - low > kTotalSettle) continue;
        if (low == 0) throw SessionError("list total already zero");
        uint64_t next = low - 1;
        *published = next;
        uint8_t raw[8];
        store_le(raw, next);
        mem.write(addr, std::span<const uint8_t>(raw, 8), false, mem.kernel_pid());
        uint64_t now = read_total(mem, addr);
        // A trailing FPGA read still shows `low` after the decrement landed.
        // Read again before publishing another decrement.
        for (int spin = 0; spin < 8 && now == low; ++spin) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            now = read_total(mem, addr);
        }
        if (now == next || (now < next && next - now <= kTotalSettle)) return;
        if (now > next) continue;
        throw SessionError("list total moved during decrement");
    }
    throw SessionError("list total did not settle");
}

// Color-list Total only. Success is a readback equal to the qword just
// written. A kernel decrement that lands below that value, or a settle
// window, is not this page's removal. Never write a stale count upward.
bool drop_color_total(Memory& mem, uint64_t addr) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        uint64_t first = read_total(mem, addr);
        uint64_t second = read_total(mem, addr);
        if (first != second) continue;
        if (first == 0) throw SessionError("list total already zero");
        uint64_t next = first - 1;
        uint64_t third = read_total(mem, addr);
        if (third != first) continue;
        uint8_t raw[8];
        store_le(raw, next);
        mem.write(addr, std::span<const uint8_t>(raw, 8), false, mem.kernel_pid());
        uint64_t now = read_total(mem, addr);
        for (int spin = 0; spin < 8 && now == first; ++spin) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            now = read_total(mem, addr);
        }
        if (now == next) return true;
        if (now > next) continue;
        throw SessionError("list total moved during decrement");
    }
    throw SessionError("list total did not settle");
}

// The zeroed aggregate counter moves by thousands of pages while a claim
// runs. Writing a stale snapshot back would raise it. When two reads will
// not settle, leave the counter alone. The color-list total is dropped by
// drop_color_total before any link store, and a miss there must not write
// the old count back. A DMA glitch is not one of these messages, so the
// caller can roll a link splice back.
bool total_settle_failure(const std::string& message) {
    return message == "list total did not settle" ||
           message == "list total moved during decrement" ||
           message == "list total already zero" || message == "list total unreadable";
}

void add_link(std::vector<PfnQword>& ops, uint64_t addr, uint64_t value) {
    ops.push_back(PfnQword{addr, value, kPfnMask, false});
}

void add_total(std::vector<PfnQword>& ops, uint64_t addr, uint64_t value) {
    ops.push_back(PfnQword{addr, value, ~uint64_t{0}, true});
}

std::optional<int> field_any(Memory& mem, std::initializer_list<const char*> types,
                             const char* field) {
    for (const char* type_name : types) {
        auto off = mem.field_offset(type_name, field);
        if (off) return off;
    }
    return std::nullopt;
}

MmpfnLayout mmpfn_layout(Memory& mem) {
    auto off = [&](const char* name, int fb) {
        auto v = field_any(mem, {"_MMPFN", "MMPFN"}, name);
        return v ? *v : fb;
    };
    auto size = mem.type_size("_MMPFN");
    if (!size) size = mem.type_size("MMPFN");
    return MmpfnLayout{
        size.value_or(0x30),
        off("u1", 0),
        off("PteAddress", 8),
        off("u2", 0x18),
        off("u3", 0x20),
        off("u4", 0x28),
        field_any(mem, {"_MMPFN", "MMPFN"}, "OriginalPte"),
    };
}

MmpfnListLayout mmpfnlist_layout(Memory& mem) {
    int size = mem.type_size("MMPFNLIST").value_or(mem.type_size("_MMPFNLIST").value_or(0x28));
    auto off = [&](const char* n, int fb) {
        auto a = mem.field_offset("MMPFNLIST", n);
        if (a) return *a;
        auto b = mem.field_offset("_MMPFNLIST", n);
        return b ? *b : fb;
    };
    return MmpfnListLayout{size, off("Total", 0), off("Flink", 0x10), off("Blink", 0x18)};
}

std::optional<uint64_t> deref_mm_pfn_database(Memory& mem) {
    auto ptr = mem.symbol("MmPfnDatabase");
    if (!ptr) {
        LOG_ERROR("nt!MmPfnDatabase was not resolved");
        return std::nullopt;
    }
    auto value = mem.read_u64(*ptr);
    if (value && *value > 0xFFFF800000000000ull) {
        LOG_INFO("nt!MmPfnDatabase=0x%llx base=0x%llx", static_cast<unsigned long long>(*ptr),
                 static_cast<unsigned long long>(*value));
        return value;
    }
    auto pa = mem.virt2phys(*ptr, mem.kernel_pid());
    std::optional<uint64_t> physical;
    if (pa) physical = mem.read_u64(*pa, true);
    LOG_ERROR("nt!MmPfnDatabase=0x%llx qword=0x%llx physical=0x%llx",
              static_cast<unsigned long long>(*ptr),
              static_cast<unsigned long long>(value.value_or(0)),
              static_cast<unsigned long long>(physical.value_or(0)));
    if (physical && *physical > 0xFFFF800000000000ull) return physical;
    return std::nullopt;
}

std::optional<uint32_t> read_list_name(Memory& mem, uint64_t head) {
    int off = field_any(mem, {"_MMPFNLIST", "MMPFNLIST"}, "ListName").value_or(0x0C);
    auto bytes = mem.read(head + off, 4);
    if (bytes.size() < 4) return std::nullopt;
    uint32_t value = 0;
    std::memcpy(&value, bytes.data(), 4);
    return value;
}

// sizeof(_MMPFNLIST) is 0x58 on 25H2 and the next list is at 0x80. Stepping by
// the struct size lands in the padding and still splices the real free list.
bool accept_list_head(Memory& mem, uint64_t head, int list_idx) {
    auto name = read_list_name(mem, head);
    if (!name || *name != static_cast<uint32_t>(list_idx)) {
        LOG_WARN("reject list head 0x%llx ListName=%s want %d",
                 static_cast<unsigned long long>(head),
                 name ? std::to_string(*name).c_str() : "unreadable", list_idx);
        return false;
    }
    return true;
}

std::unordered_map<int, uint64_t> list_heads(Memory& mem, const MmpfnListLayout&) {
    std::unordered_map<int, uint64_t> heads;
    struct Named {
        const char* name;
        int idx;
    };
    for (Named n : {Named{"MmZeroedPageListHead", kZeroedPageList},
                    Named{"MmFreePageListHead", kFreePageList},
                    Named{"MiZeroedPageListHead", kZeroedPageList},
                    Named{"MiFreePageListHead", kFreePageList}}) {
        auto va = mem.symbol(n.name);
        if (va && !heads.count(n.idx)) {
            heads[n.idx] = *va;
            LOG_INFO("%s: 0x%llx", n.name, static_cast<unsigned long long>(*va));
        }
    }
    if (heads.count(kZeroedPageList) && heads.count(kFreePageList)) return heads;
    auto part = mem.symbol("MiSystemPartition");
    if (!part) return heads;
    for (const char* type_name :
         {"_MI_PARTITION", "MI_PARTITION", "_MI_PARTITION_CORE", "MI_PARTITION_CORE"}) {
        auto off = mem.field_offset(type_name, "PageLists");
        if (!off) continue;
        uint64_t base = *part + *off;
        auto zeroed = field_any(mem, {"_MI_PARTITION_PAGE_LISTS", "MI_PARTITION_PAGE_LISTS"},
                                "ZeroedPageListHead");
        auto freed = field_any(mem, {"_MI_PARTITION_PAGE_LISTS", "MI_PARTITION_PAGE_LISTS"},
                               "FreePageListHead");
        // 25H2 pitch when the PDB has PageLists but not the child fields.
        int zeroed_off = zeroed.value_or(0);
        int free_off = freed.value_or(0x80);
        if (!heads.count(kZeroedPageList)) heads[kZeroedPageList] = base + zeroed_off;
        if (!heads.count(kFreePageList)) heads[kFreePageList] = base + free_off;
        LOG_INFO("PageLists via %s+0x%x zeroed+0x%x free+0x%x", type_name, *off, zeroed_off,
                 free_off);
        if (heads.count(kZeroedPageList) &&
            !accept_list_head(mem, heads[kZeroedPageList], kZeroedPageList)) {
            heads.erase(kZeroedPageList);
        }
        if (heads.count(kFreePageList) &&
            !accept_list_head(mem, heads[kFreePageList], kFreePageList)) {
            heads.erase(kFreePageList);
        }
        return heads;
    }
    return heads;
}

bool is_edge(Memory& mem, uint64_t db, const MmpfnLayout& layout, uint64_t pfn) {
    uint64_t va = db + pfn * layout.size;
    auto u1 = mem.read_u64(va + layout.u1);
    auto u2 = mem.read_u64(va + layout.u2);
    if (!u1 || !u2) return true;
    return flink(*u1) == kPfnTerminator || blink(*u2) == kPfnTerminator;
}

struct FreeScan {
    const std::vector<std::pair<uint64_t, uint64_t>>* ranges = nullptr;
    size_t range = 0;
    uint64_t pfn = 0;
};

std::vector<std::pair<uint64_t, std::string>> next_free_candidates(Memory& mem, FreeScan& scan,
                                                                   int limit) {
    std::vector<std::pair<uint64_t, std::string>> found;
    if (!scan.ranges) return found;
    constexpr int kBatch = 128;
    while (scan.range < scan.ranges->size() && static_cast<int>(found.size()) < limit) {
        auto [pa, cb] = (*scan.ranges)[scan.range];
        uint64_t first = (std::max)(pa >> 12, kMinPfn);
        uint64_t last = (pa + cb) >> 12;
        if (scan.pfn < first) scan.pfn = first;
        if (scan.pfn >= last) {
            ++scan.range;
            scan.pfn = 0;
            continue;
        }
        std::vector<uint64_t> chunk;
        uint64_t end = (std::min)(scan.pfn + kBatch, last);
        for (uint64_t n = scan.pfn; n < end; ++n) chunk.push_back(n);
        auto info = mem.pfn_types(chunk);
        for (uint64_t n : chunk) {
            scan.pfn = n + 1;
            auto it = info.find(n);
            if (it == info.end()) continue;
            if (it->second == "Zeroed" || it->second == "Free") {
                found.emplace_back(n, it->second);
                if (static_cast<int>(found.size()) >= limit) break;
            }
        }
    }
    return found;
}

std::optional<uint32_t> read_u32(Memory& mem, uint64_t va) {
    auto bytes = mem.read(va, 4);
    if (bytes.size() < 4) return std::nullopt;
    uint32_t value = 0;
    std::memcpy(&value, bytes.data(), 4);
    return value;
}

std::optional<int> require_field(Memory& mem, std::initializer_list<const char*> types,
                                 const char* field) {
    return field_any(mem, types, field);
}

// 4K color-list head. MiUnlinkFreeOrZeroedPage decrements this Total and the
// aggregate Zeroed/Free Total. The aggregate head is not the chain MiReplenish
// walks. PageColors[3] is the 4K color count. The pointer slot is
// FreePageInfo[3].LargePageEntries[large][list][channel][cache], reached by
// the same index the kernel uses from the start of the node.
std::optional<uint64_t> color_list_head(Memory& mem, uint64_t db, const MmpfnLayout& layout,
                                        ColorAccount& color, uint64_t pfn) {
    uint64_t va = db + layout.size * pfn;
    auto u4 = mem.read_u64(va + layout.u4);
    if (!u4) return std::nullopt;
    // bt u4, 0x28 selects the page-size adjustment in the high half of u3.
    // The kernel subtracts that 2-bit field from 3. A result of 3 is still the
    // 4K color list. Only a smaller result uses a large-page slot.
    if ((*u4 & (1ull << 40)) != 0) {
        auto hi = read_u32(mem, va + layout.u3 + 4);
        if (!hi) return std::nullopt;
        int page_size = 3 - static_cast<int>((*hi >> 27) & 3);
        if (page_size != 3) return std::nullopt;
    }
    auto e1b = mem.read(va + layout.u3 + 2, 1);
    if (e1b.empty()) return std::nullopt;
    int list = e1b[0] & 7;
    int cache = (e1b[0] >> 6) & 3;
    if (list != kZeroedPageList && list != kFreePageList) return std::nullopt;
    if (color.page_colors == 0 || color.page_colors > 256) return std::nullopt;

    uint32_t node = 0;
    auto ranges = mem.read_u64(color.ranges_va);
    if (!ranges) return std::nullopt;
    if (*ranges != 0) {
        auto last = read_u32(mem, color.last_va);
        if (!last || *last > 64) return std::nullopt;
        bool found = false;
        for (uint32_t i = 0; i <= *last; ++i) {
            auto start = mem.read_u64(*ranges + static_cast<uint64_t>(i) * 16);
            if (!start || pfn < *start) continue;
            if (i != *last) {
                auto next = mem.read_u64(*ranges + static_cast<uint64_t>(i + 1) * 16);
                if (!next || pfn >= *next) continue;
            }
            auto id = read_u32(mem, *ranges + static_cast<uint64_t>(i) * 16 + 8);
            if (!id) return std::nullopt;
            node = *id & 0x3F;
            found = true;
            break;
        }
        if (!found) return std::nullopt;
    }

    auto array = mem.read_u64(color.partition_slot);
    if (!array || *array == 0) return std::nullopt;
    uint32_t part_index = static_cast<uint32_t>((*u4 >> 43) & 0x3FF);
    auto partition = mem.read_u64(*array + static_cast<uint64_t>(part_index) * 8);
    if (!partition || *partition == 0) return std::nullopt;
    auto nodes = mem.read_u64(*partition + color.node_info_off);
    if (!nodes || *nodes == 0) return std::nullopt;
    uint64_t node_va = *nodes + static_cast<uint64_t>(node) * color.node_size;

    // 4K page-size index is 3, one channel, not a small-pfn large page.
    constexpr int kPage4k = 3;
    int channel = 0;
    int index = cache + 4 * (channel + 2 * (list + 2 * (0 + 10 * kPage4k)));
    auto base = mem.read_u64(node_va + color.entries_off + static_cast<uint64_t>(index) * 8);
    if (!base || *base == 0) return std::nullopt;
    uint32_t color_low = static_cast<uint32_t>(pfn % color.page_colors);
    return *base + static_cast<uint64_t>(color_low) * color.list_stride;
}

// Publish Active before clearing u1. Until the state byte changes, u1 is a
// list link: 0 and either end marker are what a free-list walker follows.
// PteAddress and u4 stay for the later mark_pfn_active publish. Slack is
// not pushed back onto the free list.
void hold_unlinked_frame(Memory& mem, uint64_t db, const MmpfnLayout& layout, uint64_t frame) {
    uint64_t va = db + frame * layout.size;
    uint8_t e1b = static_cast<uint8_t>(kActiveAndValid | (1 << 6));
    mem.write_kernel(va + layout.u3 + 2, std::span<const uint8_t>(&e1b, 1));
    mem.write_u64_kernel(va + layout.u2, 1);
    mem.write_u64_kernel(va + layout.u1, 0);
    uint8_t refb[2] = {1, 0};
    mem.write_kernel(va + layout.u3, std::span<const uint8_t>(refb, 2));
}

void keep_unlinked_frame(Memory& mem, uint64_t db, const MmpfnLayout& layout, uint64_t pfn,
                         std::vector<uint64_t>& claimed) {
    try {
        hold_unlinked_frame(mem, db, layout, pfn);
    } catch (const PfnRollbackError&) {
        throw;
    } catch (const std::exception& e) {
        // The frame is already off the list. Leaving it Free would make
        // the next walk treat its old link as a node. Abort the claim.
        throw PfnError(std::string("unlinked frame was not marked active: ") + e.what());
    }
    claimed.push_back(pfn);
}

std::optional<uint64_t> color_list_tail(Memory& mem, uint64_t head, const MmpfnListLayout& lists) {
    auto cur = mem.read_u64(head + lists.blink);
    if (!cur) return std::nullopt;
    uint64_t tail = blink(*cur);
    if (tail == kKernelListEnd || tail == kPfnTerminator || tail < kMinPfn) return std::nullopt;
    return tail;
}

// Pages MiReplenishPageSlist can still lock, walked from the tail back to the
// page the list head names. Stops once more than `enough` pages are confirmed:
// a Total at or below that cannot walk off the end marker. A broken link, or
// a back-chain that does not start at the head's Flink, aborts the count.
std::optional<uint64_t> reachable_color_pages(Memory& mem, uint64_t db, const MmpfnLayout& layout,
                                              uint64_t head, const MmpfnListLayout& lists,
                                              uint64_t enough) {
    auto link_at = [&](uint64_t pfn, int off) -> std::optional<uint64_t> {
        auto qword = mem.read_u64(db + layout.size * pfn + static_cast<uint64_t>(off));
        if (!qword) return std::nullopt;
        return off == layout.u1 ? flink(*qword) : blink(*qword);
    };
    auto flink_head = mem.read_u64(head + lists.flink);
    auto blink_head = mem.read_u64(head + lists.blink);
    if (!flink_head || !blink_head) return std::nullopt;
    uint64_t first = flink(*flink_head);
    uint64_t tail = blink(*blink_head);
    auto ended = [](uint64_t n) {
        return n == kKernelListEnd || n == kPfnTerminator;
    };
    if (ended(first) && ended(tail)) return 0;
    if (ended(tail) || tail < kMinPfn) return std::nullopt;
    uint64_t count = 0;
    uint64_t pfn = tail;
    uint64_t follower = 0;
    bool have_follower = false;
    while (count <= enough) {
        auto forward = link_at(pfn, layout.u1);
        if (!forward) return std::nullopt;
        if (have_follower) {
            if (*forward != follower) return std::nullopt;
        } else if (!ended(*forward)) {
            return std::nullopt;
        }
        ++count;
        if (count > enough) return count;
        auto prev = link_at(pfn, layout.u2);
        if (!prev) return std::nullopt;
        if (ended(*prev)) {
            if (pfn != first) return std::nullopt;
            return count;
        }
        if (*prev < kMinPfn) return std::nullopt;
        follower = pfn;
        have_follower = true;
        pfn = *prev;
    }
    return count;
}

// Lower Total to the reachable length. Never raise it. A missed store leaves
// the splice in place.
void cap_color_total(Memory& mem, uint64_t addr, uint64_t expected) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto first = mem.read_u64(addr);
        auto second = mem.read_u64(addr);
        if (!first || !second || *first != *second) continue;
        if (*first <= expected) return;
        try {
            PfnQword op;
            op.addr = addr;
            op.value = expected;
            op.total = true;
            write_pfn_qword(mem, op, *first);
        } catch (const PfnRollbackError&) {
            throw;
        } catch (const std::exception& e) {
            LOG_ERROR("color total 0x%llx was not lowered to %llu; splice kept, total not raised: %s",
                      static_cast<unsigned long long>(addr),
                      static_cast<unsigned long long>(expected), e.what());
            return;
        }
        LOG_INFO("color total 0x%llx lowered to %llu (was %llu)",
                 static_cast<unsigned long long>(addr),
                 static_cast<unsigned long long>(expected),
                 static_cast<unsigned long long>(*first));
        return;
    }
    LOG_ERROR("color total 0x%llx stayed above %llu; splice kept, total not raised",
              static_cast<unsigned long long>(addr), static_cast<unsigned long long>(expected));
}

// One free page identifies its color list. The tail is that list's Blink,
// which is usually not among the first free PFNs in physical order. Taking
// it makes the predecessor the new tail, so the same list is walked backward
// until the claim is full or the list refuses.
std::vector<uint64_t> claim_color_tails(Memory& mem, uint64_t db, const MmpfnLayout& layout,
                                        const MmpfnListLayout& lists,
                                        const std::vector<std::pair<uint64_t, std::string>>& candidates,
                                        int needed, const std::unordered_map<int, uint64_t>& heads,
                                        ColorAccount& color) {
    std::unordered_set<uint64_t> seen;
    std::vector<uint64_t> claimed;
    for (auto& [pfn, tp] : candidates) {
        if (static_cast<int>(claimed.size()) >= needed) break;
        int idx = tp == "Zeroed" ? kZeroedPageList : tp == "Free" ? kFreePageList : -1;
        if (idx < 0) continue;
        auto head = color_list_head(mem, db, layout, color, pfn);
        if (!head || !seen.insert(*head).second) continue;
        int removed = 0;
        while (static_cast<int>(claimed.size()) < needed) {
            auto tail = color_list_tail(mem, *head, lists);
            if (!tail) break;
            if (!unlink_one(mem, db, layout, lists, *tail, heads, idx, &color)) break;
            keep_unlinked_frame(mem, db, layout, *tail, claimed);
            ++removed;
        }
        // Replenish stops at the end marker and still lock-bts the next
        // pointer when Total is larger than the chain. Lower Total to the
        // pages still linked. A broken link is left alone. Never raise it.
        if (removed > 0) {
            try {
                auto live = mem.read_u64(*head + lists.total);
                if (live) {
                    auto reached = reachable_color_pages(mem, db, layout, *head, lists, *live);
                    if (reached && *reached < *live) {
                        cap_color_total(mem, *head + lists.total, *reached);
                    }
                }
            } catch (const PfnRollbackError&) {
                throw;
            } catch (const std::exception& e) {
                LOG_ERROR("color total 0x%llx was not capped; splice kept, total not raised: %s",
                          static_cast<unsigned long long>(*head + lists.total), e.what());
            }
        }
    }
    LOG_INFO("color lists walked: %d", static_cast<int>(seen.size()));
    return claimed;
}

std::vector<uint64_t> claim_frames(Memory& mem, uint64_t db, const MmpfnLayout& layout,
                                   const MmpfnListLayout& lists,
                                   const std::vector<std::pair<uint64_t, std::string>>& candidates,
                                   int needed, const std::unordered_map<int, uint64_t>& heads,
                                   ColorAccount* color) {
    std::vector<std::pair<uint64_t, std::string>> interior, edges;
    for (auto& c : candidates) {
        if (is_edge(mem, db, layout, c.first)) edges.push_back(c);
        else interior.push_back(c);
    }
    interior.insert(interior.end(), edges.begin(), edges.end());
    std::vector<uint64_t> claimed;
    for (auto& [pfn, tp] : interior) {
        if (static_cast<int>(claimed.size()) >= needed) break;
        int idx = tp == "Zeroed" ? kZeroedPageList : tp == "Free" ? kFreePageList : -1;
        if (idx < 0) continue;
        if (!unlink_one(mem, db, layout, lists, pfn, heads, idx, color)) continue;
        keep_unlinked_frame(mem, db, layout, pfn, claimed);
    }
    return claimed;
}

} // namespace

bool on_free_list(int loc) { return loc == kZeroedPageList || loc == kFreePageList; }

void retain_active_frames(std::vector<uint64_t> frames) {
    if (frames.empty()) return;
    static std::vector<uint64_t> held;
    held.insert(held.end(), frames.begin(), frames.end());
    LOG_ERROR("%d unlinked frame(s) stay Active and are not returned to the free list",
              static_cast<int>(frames.size()));
}

void retain_claim(const ClaimedPages& pages) {
    std::vector<uint64_t> held = pages.frames;
    held.insert(held.end(), pages.table_frames.begin(), pages.table_frames.end());
    retain_active_frames(std::move(held));
}

uint64_t set_low_pfn(uint64_t qword, uint64_t pfn) {
    return (qword & ~kPfnMask) | (pfn & kPfnMask);
}

ColorAccount color_account(Memory& mem) {
    ColorAccount account;
    auto mi = mem.symbol("MiState");
    auto channels = mem.symbol("MmNumberOfChannels");
    auto page_sizes = mem.symbol("MiPageSizes");
    auto hardware = require_field(mem, {"_MI_SYSTEM_INFORMATION"}, "Hardware");
    auto page_colors = require_field(mem, {"_MI_HARDWARE_STATE"}, "PageColors");
    auto ranges = require_field(mem, {"_MI_HARDWARE_STATE"}, "NumaMemoryRanges");
    auto last = require_field(mem, {"_MI_HARDWARE_STATE"}, "NumaLastRangeIndexInclusive");
    auto channel_ranges = require_field(mem, {"_MI_HARDWARE_STATE"}, "ChannelMemoryRanges");
    auto partitions = require_field(mem, {"_MI_SYSTEM_INFORMATION"}, "Partitions");
    auto partition = require_field(mem, {"_MI_PARTITION_STATE"}, "Partition");
    auto core = require_field(mem, {"_MI_PARTITION"}, "Core");
    auto node_info = require_field(mem, {"_MI_PARTITION_CORE"}, "NodeInformation");
    auto free_info = require_field(mem, {"_MI_NODE_INFORMATION"}, "FreePageInfo");
    auto entries = require_field(mem, {"_MI_NODE_FREE_PAGE_INFORMATION"}, "LargePageEntries");
    auto node_size = mem.type_size("_MI_NODE_INFORMATION");
    auto list_size = mem.type_size("_MMPFNLIST");
    if (!list_size) list_size = mem.type_size("MMPFNLIST");
    if (!mi || !channels || !page_sizes || !hardware || !page_colors || !ranges || !last ||
        !channel_ranges || !partitions || !partition || !core || !node_info || !free_info ||
        !entries || !node_size || *node_size <= 0 || !list_size || *list_size <= 0) {
        LOG_WARN("color list totals were left unchanged; the kernel PDB did not supply the "
                 "MiState color fields");
        return account;
    }
    auto count = read_u32(mem, *mi + *hardware + *page_colors + 3 * 4);
    auto channel_byte = mem.read(*channels, 1);
    auto page_size = mem.read_u64(*page_sizes + 3 * 8);
    if (!count || channel_byte.empty() || !page_size || *page_size != 1 || *count == 0 ||
        *count > 256) {
        LOG_WARN("color list totals were left unchanged (PageColors[3]=%s page size=%s)",
                 count ? std::to_string(*count).c_str() : "unreadable",
                 page_size ? std::to_string(*page_size).c_str() : "unreadable");
        return account;
    }
    if (channel_byte[0] > 1) {
        auto table = mem.read_u64(*mi + *hardware + *channel_ranges);
        if (!table || *table != 0) {
            LOG_WARN("color list totals were left unchanged; MmNumberOfChannels=%u and the "
                     "channel table is present",
                     channel_byte[0]);
            return account;
        }
    }
    account.enabled = true;
    account.colors_va = *mi + *hardware + *page_colors;
    account.ranges_va = *mi + *hardware + *ranges;
    account.last_va = *mi + *hardware + *last;
    account.partition_slot = *mi + *partitions + *partition;
    account.node_info_off = *core + *node_info;
    account.node_size = *node_size;
    account.entries_off = *free_info + *entries;
    account.list_stride = *list_size;
    account.page_colors = *count;
    account.channels = channel_byte[0];
    return account;
}

bool unlink_one(Memory& mem, uint64_t db, const MmpfnLayout& layout, const MmpfnListLayout& lists,
                uint64_t pfn, const std::unordered_map<int, uint64_t>& list_heads, int list_idx,
                ColorAccount* color) {
    auto note = [&](int ColorAccount::*field) {
        if (color) ++(color->*field);
    };
    auto loc = page_location(mem, db, layout, pfn);
    if (!loc || !on_free_list(*loc)) {
        note(&ColorAccount::refuse_stale);
        return false;
    }
    list_idx = *loc;
    uint64_t va = db + layout.size * pfn;
    auto u1 = mem.read_u64(va + layout.u1);
    auto u2 = mem.read_u64(va + layout.u2);
    if (!u1 || !u2) {
        note(&ColorAccount::refuse_stale);
        return false;
    }
    uint64_t nxt = flink(*u1);
    uint64_t prv = blink(*u2);
    const bool track_color = color && color->enabled;
    auto ended = [&](uint64_t n) {
        return n == kPfnTerminator || (track_color && n == kKernelListEnd);
    };
    bool is_head = ended(prv);
    bool is_tail = ended(nxt);
    auto hit = list_heads.find(list_idx);
    if (hit == list_heads.end()) {
        note(&ColorAccount::refuse_stale);
        return false;
    }
    uint64_t head_va = hit->second;
    auto same_page = [&] {
        auto loc_now = page_location(mem, db, layout, pfn);
        auto u1_now = mem.read_u64(va + layout.u1);
        auto u2_now = mem.read_u64(va + layout.u2);
        return loc_now && *loc_now == list_idx && u1_now && u2_now && flink(*u1_now) == nxt &&
               blink(*u2_now) == prv;
    };
    // MiReplenishPageSlist's continuation lock-bts the next MMPFN. On the
    // 38-one end marker it zeros that pointer and still executes the bts
    // when the color Total says another page remains, which is bugcheck 0xA
    // at address 0x18. Drop Total first, wait out a walker that already
    // sampled the old count, then publish the predecessor Flink only if this
    // page is still the tail. A count left one low is a leak. Writing it
    // back up is a PFN_LIST_CORRUPT. The detached page keeps its own links:
    // 0 or either end marker on a page that is still Free or Zeroed is what
    // that walker locks.
    if (track_color) {
        auto color_head = color_list_head(mem, db, layout, *color, pfn);
        if (!color_head) {
            note(&ColorAccount::refuse_color);
            return false;
        }
        auto color_total = mem.read_u64(*color_head + lists.total);
        if (!color_total || *color_total == 0) {
            note(&ColorAccount::refuse_empty);
            return false;
        }
        if (!is_tail) {
            note(&ColorAccount::refuse_edge);
            return false;
        }
        auto listed = mem.read_u64(*color_head + lists.blink);
        if (!listed || blink(*listed) != pfn) {
            note(&ColorAccount::refuse_edge);
            return false;
        }
        if (is_head) {
            auto cur = mem.read_u64(*color_head + lists.flink);
            if (!cur || flink(*cur) != pfn) {
                note(&ColorAccount::refuse_edge);
                return false;
            }
        }
        uint64_t p_va = 0;
        if (!is_head) {
            if (page_location(mem, db, layout, prv) != loc) {
                note(&ColorAccount::refuse_neighbor);
                return false;
            }
            p_va = db + layout.size * prv;
            auto p_u1 = mem.read_u64(p_va + layout.u1);
            if (!p_u1 || flink(*p_u1) != pfn) {
                note(&ColorAccount::refuse_neighbor);
                return false;
            }
        }
        if (!same_page()) {
            note(&ColorAccount::refuse_stale);
            return false;
        }
        try {
            drop_color_total(mem, *color_head + lists.total);
        } catch (const PfnRollbackError&) {
            throw;
        } catch (const std::exception& e) {
            LOG_DEBUG("color total for pfn 0x%llx was not dropped: %s",
                      static_cast<unsigned long long>(pfn), e.what());
            note(&ColorAccount::refuse_batch);
            return false;
        }
        ++color->decrements;
        std::this_thread::sleep_for(kColorReplenishWait);
        if (!same_page()) {
            LOG_DEBUG("color tail pfn 0x%llx moved after the total drop; total stays low",
                      static_cast<unsigned long long>(pfn));
            note(&ColorAccount::refuse_stale);
            return false;
        }
        listed = mem.read_u64(*color_head + lists.blink);
        if (!listed || blink(*listed) != pfn) {
            LOG_DEBUG("color tail pfn 0x%llx is no longer the tail; total stays low",
                      static_cast<unsigned long long>(pfn));
            note(&ColorAccount::refuse_stale);
            return false;
        }
        std::vector<PfnQword> ops;
        if (is_head) {
            auto head_flink = mem.read_u64(*color_head + lists.flink);
            if (!head_flink || flink(*head_flink) != pfn) {
                note(&ColorAccount::refuse_stale);
                return false;
            }
            // Blink first. MiReplenish walks Flink, so the end marker lands
            // there only after the back link no longer names this page.
            add_link(ops, *color_head + lists.blink, kKernelListEnd);
            add_link(ops, *color_head + lists.flink, kKernelListEnd);
        } else {
            if (page_location(mem, db, layout, prv) != loc) {
                note(&ColorAccount::refuse_stale);
                return false;
            }
            auto p_u1 = mem.read_u64(p_va + layout.u1);
            if (!p_u1 || flink(*p_u1) != pfn) {
                note(&ColorAccount::refuse_stale);
                return false;
            }
            add_link(ops, *color_head + lists.blink, prv);
            add_link(ops, p_va + layout.u1, set_low_pfn(*p_u1, kKernelListEnd));
        }
        std::vector<Backup> committed;
        try {
            committed = write_u64s(mem, ops, [&] {
                if (!is_head && page_location(mem, db, layout, prv) != loc) {
                    throw PfnError("predecessor left the free list during unlink");
                }
            });
        } catch (const PfnRollbackError&) {
            throw;
        } catch (const std::exception& e) {
            LOG_DEBUG("unlink pfn 0x%llx failed: %s", static_cast<unsigned long long>(pfn),
                      e.what());
            note(&ColorAccount::refuse_batch);
            return false;
        }
        try {
            uint64_t published = 0;
            write_fresh_total(mem, head_va + lists.total, &published);
        } catch (const PfnRollbackError&) {
            throw;
        } catch (const SessionError& e) {
            if (!total_settle_failure(e.what())) {
                restore_u64s(mem, committed);
                note(&ColorAccount::refuse_batch);
                return false;
            }
            ++color->aggregate_skips;
            LOG_DEBUG("aggregate total left unchanged for pfn 0x%llx: %s",
                      static_cast<unsigned long long>(pfn), e.what());
        }
        return true;
    }

    uint64_t splice_head = head_va;
    uint64_t end_mark = kPfnTerminator;
    std::vector<PfnQword> ops;
    if (is_head && is_tail) {
        add_link(ops, splice_head + lists.flink, end_mark);
        add_link(ops, splice_head + lists.blink, end_mark);
    } else if (is_head) {
        if (!ended(nxt) && page_location(mem, db, layout, nxt) != loc) {
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        uint64_t n_va = db + layout.size * nxt;
        auto n_u2 = mem.read_u64(n_va + layout.u2);
        if (!n_u2) {
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        add_link(ops, splice_head + lists.flink, nxt);
        add_link(ops, n_va + layout.u2, set_low_pfn(*n_u2, end_mark));
    } else if (is_tail) {
        if (!ended(prv) && page_location(mem, db, layout, prv) != loc) {
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        uint64_t p_va = db + layout.size * prv;
        auto p_u1 = mem.read_u64(p_va + layout.u1);
        if (!p_u1) {
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        add_link(ops, splice_head + lists.blink, prv);
        add_link(ops, p_va + layout.u1, set_low_pfn(*p_u1, end_mark));
    } else {
        if (page_location(mem, db, layout, prv) != loc ||
            page_location(mem, db, layout, nxt) != loc) {
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        uint64_t p_va = db + layout.size * prv;
        uint64_t n_va = db + layout.size * nxt;
        auto p_u1 = mem.read_u64(p_va + layout.u1);
        auto n_u2 = mem.read_u64(n_va + layout.u2);
        if (!p_u1 || !n_u2 || flink(*p_u1) != pfn || blink(*n_u2) != pfn) {
            // Neighbors were already spliced around this frame. Splicing
            // them again would cut a different page out of the list.
            note(&ColorAccount::refuse_neighbor);
            return false;
        }
        add_link(ops, p_va + layout.u1, set_low_pfn(*p_u1, nxt));
        add_link(ops, n_va + layout.u2, set_low_pfn(*n_u2, prv));
    }
    if (!same_page()) {
        note(&ColorAccount::refuse_stale);
        return false;
    }
    // Leave this page's own links in place. Clearing them, or storing 0 or
    // an end marker, while the state byte still says Free or Zeroed is a
    // list link a walker will follow.
    std::vector<Backup> committed;
    try {
        committed = write_u64s(mem, ops, [&] {
            if (!is_head && !ended(prv) && page_location(mem, db, layout, prv) != loc) {
                throw PfnError("predecessor left the free list during unlink");
            }
            if (!is_tail && !ended(nxt) && page_location(mem, db, layout, nxt) != loc) {
                throw PfnError("successor left the free list during unlink");
            }
        });
    } catch (const PfnRollbackError&) {
        throw;
    } catch (const std::exception& e) {
        LOG_DEBUG("unlink pfn 0x%llx failed: %s", static_cast<unsigned long long>(pfn), e.what());
        note(&ColorAccount::refuse_batch);
        return false;
    }
    // The aggregate PageLists Total is one counter for every color. The
    // zero-page thread moves it by thousands of pages during a claim, so a
    // settle miss must not undo the splice. A DMA glitch still rolls the
    // splice back from the snapshots taken before those writes.
    try {
        uint64_t published = 0;
        write_fresh_total(mem, head_va + lists.total, &published);
    } catch (const PfnRollbackError&) {
        throw;
    } catch (const SessionError& e) {
        if (!total_settle_failure(e.what())) {
            restore_u64s(mem, committed);
            note(&ColorAccount::refuse_batch);
            return false;
        }
        if (color) ++color->aggregate_skips;
        LOG_DEBUG("aggregate total left unchanged for pfn 0x%llx: %s",
                  static_cast<unsigned long long>(pfn), e.what());
    }
    return true;
}

void mark_pfn_active(Memory& mem, ClaimedPages& pages, uint64_t frame, uint64_t pte_kva,
                     uint64_t pte_frame, int used_entries, uint64_t original_pte,
                     bool table_page) {
    auto& layout = pages.layout;
    uint64_t va = pages.pfn_database + frame * layout.size;
    if (used_entries < 0 || used_entries > 512) {
        throw MappingError("page-table used count is out of range");
    }
    // A private data page has one share and one reference. A new page table
    // starts at share used+1: one for the parent entry, plus one per child
    // already published. Each later child adds a share and does not add a
    // reference. The PML4 is an existing table. It gains one share for a new
    // PDPT, and exit drops that share only when the PML4 entry is released.
    // Raising ReferenceCount with each child bugchecked 0x21.
    uint64_t u1 = 0;
    uint64_t share = 1;
    uint32_t ref = 1;
    if (table_page) {
        // A new table is not linked into the working set, so the used count
        // is in OriginalPte and u1 stays 0. Leftover free-list bits at +0x24
        // would make PageTableLinked look set.
        u1 = 0;
        share = static_cast<uint64_t>(used_entries) + 1;
        ref = 1;
        original_pte = (original_pte & ~(kUsedPteMask << kOrigUsedShift)) |
                       (static_cast<uint64_t>(used_entries) << kOrigUsedShift);
    }
    // Active before u1 is cleared. While the state byte still says Free or
    // Zeroed, u1 is a list link: 0 bugchecks 0xA, and the 40-bit end marker
    // makes a walker drop the rest of the list. Cache attribute 1 (bit 6) is
    // cached. Bits 3-5 (WriteInProgress, Modified, ReadInProgress) are
    // cleared so a later share decrement cannot queue the frame on the
    // Modified list while its PTE is still present (bugcheck 0x4E/0x99).
    uint64_t e1_va = va + layout.u3 + 2;
    uint8_t e1b = static_cast<uint8_t>(kActiveAndValid | (1 << 6));
    mem.write_kernel(e1_va, std::span<const uint8_t>(&e1b, 1));
    mem.write_u64_kernel(va + layout.u2, share);
    mem.write_u64_kernel(va + layout.u1, u1);
    mem.write_u64_kernel(va + layout.pte_address, pte_kva);
    uint8_t refb[2] = {static_cast<uint8_t>(ref & 0xFF), static_cast<uint8_t>((ref >> 8) & 0xFF)};
    mem.write_kernel(va + layout.u3, std::span<const uint8_t>(refb, 2));
    auto u4 = mem.read_u64(va + layout.u4).value_or(0);
    mem.write_u64_kernel(va + layout.u4, set_low_pfn(u4, pte_frame));
    if (table_page) {
        uint8_t flags5[4] = {};
        mem.write_kernel(va + kPfnFlags5, std::span<const uint8_t>(flags5, 4));
    }
    if (layout.original_pte) {
        int orig = *layout.original_pte;
        if (orig != layout.u1 && orig != layout.u2 && orig != layout.pte_address &&
            orig != layout.u3 && orig != layout.u4) {
            mem.write_u64_kernel(va + orig, original_pte);
        }
    }
}

ClaimedPages allocate_physical_pages(Memory& mem, uint64_t size) {
    if (size == 0 || size > 0x7FFFFFFF000ull) {
        throw PfnError("allocation does not fit a page count");
    }
    int page_count = static_cast<int>((size + kPageSize - 1) / kPageSize);
    int needed = page_count + kTableSlack;
    auto db = deref_mm_pfn_database(mem);
    auto layout = mmpfn_layout(mem);
    auto lists = mmpfnlist_layout(mem);
    LOG_INFO("MmPfnDatabase=0x%llx MMPFN=0x%x", static_cast<unsigned long long>(db.value_or(0)),
             layout.size);
    if (!mem.type_size("_MMPFN") && !mem.type_size("MMPFN")) {
        LOG_WARN("MMPFN size fell back to 0x30 because the kernel PDB did not supply it");
    }
    if (!db) {
        throw PfnError("MmPfnDatabase is unavailable. dbghelp.dll and symsrv.dll must sit next to "
                       "vmm.dll, and the analysis PC must reach the Microsoft symbol server.");
    }
    auto ranges = mem.phys_map();
    if (ranges.empty()) {
        throw PfnError("physical memory map is empty; refusing to scan PFNs");
    }
    auto heads = list_heads(mem, lists);
    if (heads.empty()) {
        throw PfnError("no MMPFN list heads (Mm*PageListHead / MiSystemPartition.PageLists). "
                       "Refusing to unlink: a missed head corrupts the free-list walk.");
    }
    auto color = color_account(mem);
    // The first free pages in physical order are often interior nodes. A
    // color list is harvested from its Blink, which names the only page that
    // list will give up. 32768 is a bound so a machine with no resolvable
    // color list still returns.
    constexpr int kBatch = 256;
    constexpr int kMaxFree = 32768;
    FreeScan scan{&ranges, 0, 0};
    std::vector<uint64_t> claimed;
    int examined = 0;
    while (static_cast<int>(claimed.size()) < needed && examined < kMaxFree) {
        auto batch = next_free_candidates(mem, scan, kBatch);
        if (batch.empty()) break;
        examined += static_cast<int>(batch.size());
        int still = needed - static_cast<int>(claimed.size());
        auto more = color.enabled ? claim_color_tails(mem, *db, layout, lists, batch, still, heads,
                                                      color)
                                  : claim_frames(mem, *db, layout, lists, batch, still, heads,
                                                 nullptr);
        claimed.insert(claimed.end(), more.begin(), more.end());
    }
    LOG_INFO("Free/Zeroed candidates examined: %d", examined);
    if (color.enabled) {
        LOG_INFO("color list totals decremented: %d (PageColors[3]=%u channels=%u, "
                 "aggregate totals left racing: %d)",
                 color.decrements, color.page_colors, color.channels, color.aggregate_skips);
        LOG_INFO("pfn claim refused: color=%d empty=%d edge=%d neighbor=%d stale=%d batch=%d",
                 color.refuse_color, color.refuse_empty, color.refuse_edge, color.refuse_neighbor,
                 color.refuse_stale, color.refuse_batch);
    }
    LOG_INFO("claimed %d frames (need %d data + slack)", static_cast<int>(claimed.size()),
             page_count);
    if (static_cast<int>(claimed.size()) < page_count) {
        retain_active_frames(claimed);
        throw PfnError("only a partial PFN claim; refusing a short mapping");
    }
    ClaimedPages out;
    out.page_count = page_count;
    out.frames.assign(claimed.begin(), claimed.begin() + page_count);
    out.table_frames.assign(claimed.begin() + page_count, claimed.end());
    out.pfn_database = *db;
    out.layout = layout;
    out.list_heads = heads;
    out.list_layout = lists;
    out.spare = out.table_frames;
    return out;
}

} // namespace dma_hello
