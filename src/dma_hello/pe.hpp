// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "dma_hello/memory.hpp"
#include "dma_hello/process.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dma_hello {

struct Section {
    std::string name;
    uint32_t va = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t raw_size = 0;
};

struct Import {
    std::string dll;
    std::optional<std::string> name;
    std::optional<uint16_t> ordinal;
    uint32_t iat_rva = 0;
};

struct PeImage {
    std::vector<uint8_t> data;
    uint64_t preferred_base = 0;
    uint32_t entry_rva = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    std::vector<Section> sections;
    std::unordered_map<std::string, uint32_t> exports;
    std::vector<Import> imports;
    std::vector<std::pair<uint32_t, int>> relocs; // rva, type

    static PeImage load(const std::string& path);
    static PeImage parse(std::vector<uint8_t> data);

    std::vector<uint8_t> mapped(uint64_t base) const;
    std::optional<uint64_t> entry_va(uint64_t base) const;
    uint64_t export_va(uint64_t base, const std::string& name) const;
};

void write_image(Memory& mem, const Target& target, uint64_t base,
                 std::span<const uint8_t> image);
void resolve_imports(Memory& mem, const Target& target, uint64_t base, const PeImage& pe);
std::vector<std::string> module_candidates(const std::string& dll);
void apply_relocs(std::vector<uint8_t>& buf, const std::vector<std::pair<uint32_t, int>>& relocs,
                  int64_t delta);

} // namespace dma_hello
