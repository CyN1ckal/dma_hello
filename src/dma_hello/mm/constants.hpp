// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

namespace dma_hello {

inline constexpr uint64_t kPageSize = 0x1000;
inline constexpr uint64_t kPageMask = 0xFFF;
inline constexpr uint64_t kPteAddrMask = 0x000FFFFFFFFFF000ull;
inline constexpr uint64_t kPtePfnMax = (1ull << 40) - 1;
inline constexpr uint64_t kPteP = 1;
inline constexpr uint64_t kPteRw = 1ull << 1;
inline constexpr uint64_t kPteUs = 1ull << 2;
inline constexpr uint64_t kPtePs = 1ull << 7;
inline constexpr uint64_t kPteNx = 1ull << 63;
// _MI_ACTIVE_PFN page-table view of u1. Bits 32-41 are UsedPageTableEntries.
// On a 4K leaf PTE, bit 7 is PAT, not the large-page bit.
// _MI_PFN_FLAGS5.PageTableLinked (bit 26 of the dword at +0x24) selects which
// field 0x41790 reads. Set: u1 bits 32-41. Clear: OriginalPte bits 16-25.
inline constexpr int kUsedPteShift = 32;
inline constexpr int kOrigUsedShift = 16;
inline constexpr int kPageTableLinkedBit = 26;
inline constexpr uint64_t kUsedPteMask = 0x3FF;
inline constexpr int kPfnFlags5 = 0x24;
// _MIPFNBLINK: ShareCount is the low 62 bits. The top two bits are the lock
// and delete flags and must survive a charge update.
inline constexpr uint64_t kShareCountMask = (1ull << 62) - 1;
inline constexpr uint64_t kDefaultPteBase = 0xFFFFF68000000000ull;
inline constexpr uint32_t kPageExecuteReadWrite = 0x40;
inline constexpr uint32_t kProtWrite = 0x04 | 0x08 | 0x40 | 0x80;
inline constexpr uint32_t kProtExec = 0x10 | 0x20 | 0x40 | 0x80;
// Germanium (24H2/25H2) stores Flink, Blink, and PteFrame in 40 bits.
// The list end marker is 40 ones. A 36-one value is a normal PFN.
inline constexpr int kPfnBits = 40;
inline constexpr uint64_t kPfnMask = (1ull << kPfnBits) - 1;
inline constexpr uint64_t kPfnTerminator = kPfnMask;
// Color lists end with 38 ones. That marker is not the 40-one PFN terminator.
// The replenish walk trusts the color-list Total, so Total must not exceed
// the reachable chain.
inline constexpr uint64_t kKernelListEnd = 0x3FFFFFFFFFull;
inline constexpr int kZeroedPageList = 0;
inline constexpr int kFreePageList = 1;
inline constexpr int kActiveAndValid = 6;
// Each claim takes this many extra frames and leaves unused ones Active until reboot.
inline constexpr int kTableSlack = 32;
inline constexpr uint64_t kMinPfn = 0x100;

} // namespace dma_hello
