// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/mm/page_tables.hpp"

#include "dma_hello/bytes.hpp"
#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"

#include <algorithm>
#include <array>

namespace dma_hello {
namespace {

std::array<int, 4> indices(uint64_t va) {
    return {static_cast<int>((va >> 39) & 0x1FF), static_cast<int>((va >> 30) & 0x1FF),
            static_cast<int>((va >> 21) & 0x1FF), static_cast<int>((va >> 12) & 0x1FF)};
}

struct Level {
    uint64_t pa = 0;
    uint64_t pfn = 0;
};

// A new table is charged and filled before this parent slot is written, so a
// walker never sees a present pointer to an empty or still-free frame.
struct PendingLink {
    uint64_t slot = 0;
    uint64_t entry = 0;
    uint64_t table_pfn = 0;
};

struct InstallState {
    std::vector<NewTable> new_tables;
};

// MM_READWRITE. Page-table pages are private demand-zero, not executable.
constexpr uint64_t kTableDemandZero = 4ull << 5;

uint64_t pfn_va(const ClaimedPages& pages, uint64_t pfn) {
    return pages.pfn_database + pfn * static_cast<uint64_t>(pages.layout.size);
}

// A linked table keeps UsedPageTableEntries in u1. An unlinked table,
// including every table this allocator creates, keeps that count in
// OriginalPte. Every table gains one ShareCount per child. ReferenceCount
// stays where it was; raising it per child bugchecks 0x21.
bool page_table_linked(Memory& mem, uint64_t base) {
    auto raw = mem.read(base + kPfnFlags5, 4);
    if (raw.size() != 4) throw MappingError("page-table flags unreadable");
    uint32_t flags = load_le<uint32_t>(raw.data());
    return (flags & (1u << kPageTableLinkedBit)) != 0;
}

void add_used_page_table_entries(Memory& mem, ClaimedPages& pages, uint64_t table_pfn, int add) {
    if (add <= 0) return;
    uint64_t base = pfn_va(pages, table_pfn);
    bool linked = page_table_linked(mem, base);
    uint64_t count = 0;
    if (linked) {
        auto u1 = mem.read_u64(base + pages.layout.u1);
        if (!u1) throw MappingError("page-table PFN unreadable");
        count = (*u1 >> kUsedPteShift) & kUsedPteMask;
    } else {
        if (!pages.layout.original_pte) {
            throw MappingError("OriginalPte offset missing");
        }
        auto pte = mem.read_u64(base + *pages.layout.original_pte);
        if (!pte) throw MappingError("page-table OriginalPte unreadable");
        count = (*pte >> kOrigUsedShift) & kUsedPteMask;
    }
    if (count + static_cast<uint64_t>(add) > 512) {
        throw MappingError("UsedPageTableEntries would exceed 512");
    }
    uint64_t used = count + static_cast<uint64_t>(add);
    if (linked) {
        auto u1 = mem.read_u64(base + pages.layout.u1);
        if (!u1) throw MappingError("page-table PFN unreadable");
        uint64_t merged = (*u1 & ~(kUsedPteMask << kUsedPteShift)) | (used << kUsedPteShift);
        mem.write_u64_kernel(base + pages.layout.u1, merged);
    } else {
        auto pte = mem.read_u64(base + *pages.layout.original_pte);
        if (!pte) throw MappingError("page-table OriginalPte unreadable");
        uint64_t merged = (*pte & ~(kUsedPteMask << kOrigUsedShift)) | (used << kOrigUsedShift);
        mem.write_u64_kernel(base + *pages.layout.original_pte, merged);
    }

    auto u2 = mem.read_u64(base + pages.layout.u2);
    if (!u2) throw MappingError("page-table share count unreadable");
    uint64_t share = *u2 & kShareCountMask;
    if (share + static_cast<uint64_t>(add) > kShareCountMask) {
        throw MappingError("page-table share count would overflow");
    }
    uint64_t share_next = share + static_cast<uint64_t>(add);
    mem.write_u64_kernel(base + pages.layout.u2, (*u2 & ~kShareCountMask) | share_next);
    LOG_INFO("page-table pfn 0x%llx used %llu -> %llu share %llu -> %llu%s",
             static_cast<unsigned long long>(table_pfn), static_cast<unsigned long long>(count),
             static_cast<unsigned long long>(used), static_cast<unsigned long long>(share),
             static_cast<unsigned long long>(share_next), linked ? "" : " (OriginalPte)");
}

void commit_pte(Memory& mem, ClaimedPages& pages, uint64_t slot, uint64_t entry,
                uint64_t table_pfn) {
    add_used_page_table_entries(mem, pages, table_pfn, 1);
    mem.write_u64(slot, entry, true);
}

// pending is root-first. Publishing it backwards links the leaf table only
// after that table has a child, then links each parent the same way.
void publish_pending(Memory& mem, ClaimedPages& pages, std::vector<PendingLink>& pending) {
    for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
        commit_pte(mem, pages, it->slot, it->entry, it->table_pfn);
    }
    pending.clear();
}

Level ensure_table(Memory& mem, ClaimedPages& pages, uint64_t table_pa, int index,
                   std::vector<uint64_t>& table_frames, InstallState& st,
                   std::vector<PendingLink>& pending, uint64_t parent_pfn, uint64_t entry_kva,
                   bool nx) {
    uint64_t slot = table_pa + static_cast<uint64_t>(index) * 8;
    auto entry = mem.read_u64(slot, true);
    if (!entry) throw MappingError("phys read failed at page-table slot");
    if (*entry & kPteP) {
        if (*entry & kPtePs) throw MappingError("large page in the walk; refusing");
        // Execute is allowed only when every level is executable. Windows leaves
        // NX set on a PDPTE or PDE that was created for a non-executable VAD.
        // A new leaf under that entry still faults as an instruction fetch
        // (0xC0000005, exception information 8) even though the leaf PTE has NX
        // clear. Clearing NX here does not make sibling pages executable: their
        // own entries keep the bit.
        if (!nx && (*entry & kPteNx)) {
            mem.write_u64(slot, *entry & ~kPteNx, true);
            LOG_INFO("cleared NX on existing table pfn 0x%llx index %d",
                     static_cast<unsigned long long>(parent_pfn), index);
        }
        uint64_t pa = *entry & kPteAddrMask;
        return Level{pa, pa >> 12};
    }
    if (table_frames.empty()) throw MappingError("no free PFN left for a page table");
    uint64_t pfn = table_frames.front();
    table_frames.erase(table_frames.begin());
    uint64_t new_pa = pfn << 12;
    std::vector<uint8_t> zero(kPageSize, 0);
    mem.write(new_pa, zero, true);
    // The parent PTE stays pending until this table has a child. Reference
    // count stays 1. Share count starts at 1, the residency held by the parent
    // entry, and rises once more for each child.
    mark_pfn_active(mem, pages, pfn, entry_kva, parent_pfn, 0, kTableDemandZero, true);
    st.new_tables.push_back(NewTable{pfn, parent_pfn, entry_kva});
    uint64_t new_entry = new_pa | kPteP | kPteRw | kPteUs;
    if (nx) new_entry |= kPteNx;
    pending.push_back(PendingLink{slot, new_entry, parent_pfn});
    return Level{new_pa, pfn};
}

struct Slot {
    uint64_t slot_pa = 0;
    uint64_t pt_pfn = 0;
    std::vector<PendingLink> pending;
};

Slot pte_slot(Memory& mem, ClaimedPages& pages, uint64_t cr3, uint64_t va,
              std::vector<uint64_t>& table_frames, InstallState& st, bool nx) {
    auto [i4, i3, i2, i1] = indices(va);
    uint64_t pml4 = cr3 & kPteAddrMask;
    uint64_t pml4_pfn = pml4 >> 12;
    Slot slot;
    auto pdpt = ensure_table(mem, pages, pml4, i4, table_frames, st, slot.pending, pml4_pfn,
                             table_entry_kernel_va(mem, va, 3), nx);
    auto pd = ensure_table(mem, pages, pdpt.pa, i3, table_frames, st, slot.pending, pdpt.pfn,
                           table_entry_kernel_va(mem, va, 2), nx);
    auto pt = ensure_table(mem, pages, pd.pa, i2, table_frames, st, slot.pending, pd.pfn,
                           table_entry_kernel_va(mem, va, 1), nx);
    slot.slot_pa = pt.pa + static_cast<uint64_t>(i1) * 8;
    slot.pt_pfn = pt.pfn;
    return slot;
}

void install_leaf(Memory& mem, ClaimedPages& pages, Slot& slot, uint64_t va, uint64_t frame,
                  uint32_t protection) {
    auto existing = mem.read_u64(slot.slot_pa, true);
    if (existing && (*existing & kPteP)) {
        throw MappingError("PTE already present; not stealing");
    }
    // The data frame is Active before its leaf is visible. The leaf charges
    // the table before a new parent pointer is published.
    mark_pfn_active(mem, pages, frame, pte_kernel_va(mem, va), slot.pt_pfn, 0,
                    demand_zero_soft_pte(protection), false);
    commit_pte(mem, pages, slot.slot_pa, encode_pte(frame, protection), slot.pt_pfn);
    publish_pending(mem, pages, slot.pending);
}

int pages_until_boundary(uint64_t va, uint64_t span) {
    uint64_t aligned = va & ~(span - 1);
    uint64_t next = aligned + span;
    if (next <= va) return 1;
    return static_cast<int>((next - va) / kPageSize);
}

} // namespace

uint64_t encode_pte(uint64_t frame, uint32_t protection) {
    if (frame > kPtePfnMax) throw MappingError("page frame does not fit in PTE bits 12-51");
    uint64_t pte = kPteP | kPteUs;
    if (protection & kProtWrite) pte |= kPteRw;
    pte |= (frame << 12) & kPteAddrMask;
    if (!(protection & kProtExec)) pte |= kPteNx;
    return pte;
}

uint64_t demand_zero_soft_pte(uint32_t protection) {
    // MM_READONLY=1, MM_EXECUTE_READ=3, MM_READWRITE=4, MM_EXECUTE_READWRITE=6.
    bool write = (protection & kProtWrite) != 0;
    bool exec = (protection & kProtExec) != 0;
    uint32_t mm = 1;
    if (write && exec) mm = 6;
    else if (exec) mm = 3;
    else if (write) mm = 4;
    return static_cast<uint64_t>(mm) << 5;
}

uint64_t pte_kernel_va(Memory& mem, uint64_t va) {
    auto ptr = mem.symbol("MmPteBase");
    if (!ptr || !*ptr) throw MappingError("MmPteBase is unavailable");
    auto value = mem.read_u64(*ptr);
    // The address of the symbol is not the PTE base. A missing or non-canonical
    // qword is refused so PteAddress cannot name the wrong slot.
    if (!value || *value <= 0xFFFF800000000000ull) {
        throw MappingError("MmPteBase is not a canonical kernel address");
    }
    uint64_t canon = va & 0x0000FFFFFFFFFFFFull;
    return *value + ((canon >> 9) & 0x7FFFFFFFF8ull);
}

uint64_t table_entry_kernel_va(Memory& mem, uint64_t va, int level) {
    uint64_t addr = va;
    for (int i = 0; i < level + 1; ++i) addr = pte_kernel_va(mem, addr);
    return addr;
}

RangeBlock range_block(Memory& mem, uint64_t cr3, uint64_t base_va, int page_count) {
    if (!cr3 || page_count <= 0) return RangeBlock::Unreadable;
    // Spans covered by one missing entry. A missing PDE covers 2 MiB, so the
    // rest of that region does not need its own read.
    constexpr uint64_t kGd = 512ull * 1024 * 1024 * 1024;
    constexpr uint64_t kPdpt = 1024ull * 1024 * 1024;
    constexpr uint64_t kPd = 2ull * 1024 * 1024;
    int index = 0;
    while (index < page_count) {
        uint64_t va = base_va + static_cast<uint64_t>(index) * kPageSize;
        auto [i4, i3, i2, i1] = indices(va);
        int idx[3] = {i4, i3, i2};
        uint64_t span[3] = {kGd, kPdpt, kPd};
        uint64_t table = cr3 & kPteAddrMask;
        bool leaf = true;
        for (int level = 0; level < 3; ++level) {
            auto entry = mem.read_u64(table + static_cast<uint64_t>(idx[level]) * 8, true);
            if (!entry) return RangeBlock::Unreadable;
            if (!(*entry & kPteP)) {
                int skip = pages_until_boundary(va, span[level]);
                if (skip < 1) skip = 1;
                index += skip;
                leaf = false;
                break;
            }
            if (*entry & kPtePs) return RangeBlock::Large;
            table = *entry & kPteAddrMask;
        }
        if (!leaf) continue;
        auto pte = mem.read_u64(table + static_cast<uint64_t>(i1) * 8, true);
        if (!pte) return RangeBlock::Unreadable;
        // Bit 7 of a 4K PTE is PAT. Only a non-zero slot is occupied.
        if (*pte & kPteP) return RangeBlock::Present;
        if (*pte != 0) return RangeBlock::Software;
        ++index;
    }
    return RangeBlock::Clear;
}

std::optional<PteSlot> existing_pte_slot(Memory& mem, uint64_t cr3, uint64_t va) {
    auto [i4, i3, i2, i1] = indices(va);
    uint64_t pml4 = cr3 & kPteAddrMask;
    auto step = [&](uint64_t table_pa, int index) -> std::optional<uint64_t> {
        uint64_t slot = table_pa + static_cast<uint64_t>(index) * 8;
        auto entry = mem.read_u64(slot, true);
        if (!entry || !(*entry & kPteP)) return std::nullopt;
        if (*entry & kPtePs) return std::nullopt;
        return *entry & kPteAddrMask;
    };
    auto pdpt = step(pml4, i4);
    if (!pdpt) return std::nullopt;
    auto pd = step(*pdpt, i3);
    if (!pd) return std::nullopt;
    auto pt = step(*pd, i2);
    if (!pt) return std::nullopt;
    uint64_t slot = *pt + static_cast<uint64_t>(i1) * 8;
    auto pte = mem.read_u64(slot, true);
    if (!pte) return std::nullopt;
    return PteSlot{slot, *pte, (*pt) >> 12};
}

uint64_t virt_to_phys(Memory& mem, uint64_t cr3, uint64_t va) {
    auto found = existing_pte_slot(mem, cr3, va);
    if (!found) throw MappingError("no PTE for VA");
    if (!(found->pte & kPteP)) throw MappingError("PTE is not present");
    return (found->pte & kPteAddrMask) | (va & (kPageSize - 1));
}

void write_process_va(Memory& mem, uint64_t cr3, uint64_t va, std::span<const uint8_t> data,
                      uint32_t pid) {
    size_t off = 0;
    uint64_t addr = va;
    while (off < data.size()) {
        uint64_t page_off = addr & (kPageSize - 1);
        size_t n = (std::min)(data.size() - off, static_cast<size_t>(kPageSize - page_off));
        auto chunk = data.subspan(off, n);
        try {
            uint64_t pa = virt_to_phys(mem, cr3, addr);
            mem.write(pa, chunk, true);
        } catch (const MappingError&) {
            mem.write(addr, chunk, false, pid);
        }
        addr += n;
        off += n;
    }
}

StagedCow stage_cow_page(Memory& mem, uint64_t cr3, uint64_t va, uint64_t new_frame) {
    auto found = existing_pte_slot(mem, cr3, va);
    if (!found) throw MappingError("no PTE; cannot COW");
    if (!(found->pte & kPteP)) throw MappingError("PTE is not present");
    uint64_t old_pa = found->pte & kPteAddrMask;
    auto data = mem.read(old_pa, kPageSize, true);
    if (data.size() < kPageSize) throw MappingError("COW source is short");
    mem.write(new_frame << 12, data, true);
    uint64_t new_pte = kPteP | kPteRw | kPteUs | ((new_frame << 12) & kPteAddrMask);
    new_pte |= (1ull << 5) | (1ull << 6);
    if (found->pte & kPteNx) new_pte |= kPteNx;
    return StagedCow{found->slot_pa, found->pt_pfn, new_pte, old_pa >> 12};
}

void publish_cow_pte(Memory& mem, const StagedCow& cow) {
    mem.write_u64(cow.slot_pa, cow.new_pte, true);
}

void refuse_occupied(RangeBlock block) {
    if (block == RangeBlock::Clear) return;
    if (block == RangeBlock::Large) throw MappingError("large page in the walk; refusing");
    if (block == RangeBlock::Unreadable) throw MappingError("page table unreadable");
    throw MappingError("PTE already present; not stealing");
}

void map_range(Memory& mem, uint64_t cr3, ClaimedPages& pages, uint64_t base_va,
               uint32_t protection, bool* published) {
    if (published) *published = false;
    if (static_cast<int>(pages.frames.size()) < pages.page_count) {
        throw MappingError("not enough claimed frames for PTE programming");
    }
    if (!cr3) throw MappingError("CR3 is 0");
    // Reject the whole range before any parent PTE or leaf is written.
    refuse_occupied(range_block(mem, cr3, base_va, pages.page_count));
    if (published) *published = true;
    LOG_INFO("mapping %d pages at VA 0x%llx CR3=0x%llx", pages.page_count,
             static_cast<unsigned long long>(base_va), static_cast<unsigned long long>(cr3));
    InstallState st;
    bool nx_tables = !(protection & kProtExec);
    auto table_frames = pages.table_frames;
    int mapped = 0;
    for (int i = 0; i < pages.page_count; ++i) {
        uint64_t va = base_va + static_cast<uint64_t>(i) * kPageSize;
        uint64_t frame = pages.frames[i];
        auto slot = pte_slot(mem, pages, cr3, va, table_frames, st, nx_tables);
        install_leaf(mem, pages, slot, va, frame, protection);
        ++mapped;
    }
    pages.table_frames = table_frames;
    pages.spare = table_frames;
    LOG_INFO("mapped %d/%d pages (%d new tables)", mapped, pages.page_count,
             static_cast<int>(st.new_tables.size()));
}

void map_one_page(Memory& mem, uint64_t cr3, ClaimedPages& pages, uint64_t va, uint64_t frame,
                  uint32_t protection, bool* published) {
    if (published) *published = false;
    if (!cr3) throw MappingError("CR3 is 0");
    refuse_occupied(range_block(mem, cr3, va, 1));
    if (published) *published = true;
    InstallState st;
    bool nx_tables = !(protection & kProtExec);
    auto slot = pte_slot(mem, pages, cr3, va, pages.spare, st, nx_tables);
    install_leaf(mem, pages, slot, va, frame, protection);
    pages.table_frames = pages.spare;
}

} // namespace dma_hello
