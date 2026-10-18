// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/memory.hpp"

#include "dma_hello/log.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

namespace dma_hello {
namespace {

std::string hex_bytes(std::span<const uint8_t> data) {
    std::string out;
    out.reserve(data.size() * 2);
    static constexpr char kHex[] = "0123456789abcdef";
    for (uint8_t byte : data) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

// FPGA reads can trail a write that already landed. Retry the read before
// treating the write as lost. Sleep only after a mismatch.
bool read_matches(Memory& mem, uint64_t address, std::span<const uint8_t> data, bool physical,
                  std::vector<uint8_t>* last) {
    const uint32_t pid = physical ? 0 : mem.kernel_pid();
    for (int attempt = 0; attempt < 8; ++attempt) {
        try {
            auto back = mem.read(address, data.size(), physical, pid);
            if (last) *last = back;
            if (back.size() == data.size() &&
                std::equal(back.begin(), back.end(), data.begin())) {
                return true;
            }
        } catch (const SessionError&) {
            if (last) last->clear();
        }
        if (attempt + 1 < 8) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

} // namespace

std::optional<uint64_t> Memory::read_u64(uint64_t address, bool physical, uint32_t pid) {
    auto data = read(address, 8, physical, pid);
    if (data.size() < 8) return std::nullopt;
    return load_le<uint64_t>(data.data());
}

void Memory::write_u64(uint64_t address, uint64_t value, bool physical, uint32_t pid) {
    uint8_t b[8];
    store_le(b, value);
    write(address, std::span<const uint8_t>(b, 8), physical, pid);
}

void Memory::write_kernel(uint64_t address, std::span<const uint8_t> data) {
    bool virtual_ok = false;
    try {
        write(address, data, false, kernel_pid());
        virtual_ok = true;
    } catch (const SessionError& e) {
        // "dma glitch" and other injected failures must reach the caller so a
        // PFN unlink can roll back. Only a rejected write falls through to PA.
        if (std::string(e.what()) != "write failed") throw;
        LOG_DEBUG("kernel VA write 0x%llx failed: %s", static_cast<unsigned long long>(address),
                  e.what());
    }
    if (virtual_ok && read_matches(*this, address, data, false, nullptr)) return;
    if (virtual_ok) {
        LOG_DEBUG("kernel VA 0x%llx write did not stick; trying physical",
                  static_cast<unsigned long long>(address));
    }
    auto pa = virt2phys(address, kernel_pid());
    if (!pa) {
        // A virtual write that returned success but did not read back is not
        // a landed kernel update. Callers of share counts and list links must
        // not continue.
        throw SessionError(virtual_ok ? "kernel VA write did not stick and has no physical translation"
                                      : "kernel VA is not mapped and has no physical translation");
    }
    write(*pa, data, true, 0);
    std::vector<uint8_t> got;
    if (!read_matches(*this, *pa, data, true, &got)) {
        LOG_ERROR("physical write verify failed va=0x%llx pa=0x%llx want=%s got=%s",
                  static_cast<unsigned long long>(address),
                  static_cast<unsigned long long>(*pa), hex_bytes(data).c_str(),
                  hex_bytes(got).c_str());
        throw SessionError("physical write verify failed");
    }
}

void Memory::write_u64_kernel(uint64_t address, uint64_t value) {
    uint8_t b[8];
    store_le(b, value);
    write_kernel(address, std::span<const uint8_t>(b, 8));
}

} // namespace dma_hello
