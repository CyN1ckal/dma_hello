// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/pe.hpp"

#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"
#include "dma_hello/mm/page_tables.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <exception>
#include <fstream>

namespace dma_hello {
namespace {

constexpr uint32_t kRelDir64 = 10;
constexpr uint32_t kRelHighLow = 3;
constexpr uint64_t kOrdinalFlag = 1ull << 63;

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::vector<uint8_t> file_bytes(const std::vector<uint8_t>& data, const std::vector<Section>& secs,
                                uint32_t rva, size_t n, uint32_t header_limit = 0x1000) {
    if (rva < header_limit) {
        if (rva + n > data.size()) throw PayloadError("header RVA is short");
        return {data.begin() + rva, data.begin() + rva + static_cast<ptrdiff_t>(n)};
    }
    for (auto& s : secs) {
        uint32_t size = (std::max)(s.virtual_size, s.raw_size);
        if (s.va <= rva && rva < s.va + size) {
            uint32_t off = s.raw_ptr + (rva - s.va);
            if (off + n > data.size()) throw PayloadError("section RVA is short");
            return {data.begin() + off, data.begin() + off + static_cast<ptrdiff_t>(n)};
        }
    }
    throw PayloadError("cannot translate RVA to a file offset");
}

uint32_t u32(const std::vector<uint8_t>& data, const std::vector<Section>& secs, uint32_t rva) {
    auto b = file_bytes(data, secs, rva, 4);
    return load_le<uint32_t>(b.data());
}

uint64_t u64(const std::vector<uint8_t>& data, const std::vector<Section>& secs, uint32_t rva) {
    auto b = file_bytes(data, secs, rva, 8);
    return load_le<uint64_t>(b.data());
}

std::string cstring(const std::vector<uint8_t>& data, const std::vector<Section>& secs,
                    uint32_t rva) {
    auto raw = file_bytes(data, secs, rva, 256);
    auto z = std::find(raw.begin(), raw.end(), 0);
    return {raw.begin(), z};
}

std::unordered_map<std::string, uint32_t> parse_exports(const std::vector<uint8_t>& data,
                                                        const std::vector<Section>& secs,
                                                        uint32_t rva, uint32_t size) {
    if (!rva || !size) return {};
    auto raw = file_bytes(data, secs, rva, 40);
    uint32_t nnames = load_le<uint32_t>(raw.data() + 24);
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames at 24, AddressOfFunctions at 28,
    // AddressOfNames at 32, AddressOfNameOrdinals at 36.
    uint32_t funcs_rva = load_le<uint32_t>(raw.data() + 28);
    uint32_t names_rva = load_le<uint32_t>(raw.data() + 32);
    uint32_t ords_rva = load_le<uint32_t>(raw.data() + 36);
    std::unordered_map<std::string, uint32_t> exports;
    for (uint32_t i = 0; i < nnames; ++i) {
        uint32_t name_rva = u32(data, secs, names_rva + i * 4);
        auto ord_bytes = file_bytes(data, secs, ords_rva + i * 2, 2);
        uint16_t ordinal_index = load_le<uint16_t>(ord_bytes.data());
        uint32_t func_rva = u32(data, secs, funcs_rva + ordinal_index * 4);
        exports[cstring(data, secs, name_rva)] = func_rva;
    }
    return exports;
}

std::vector<Import> parse_imports(const std::vector<uint8_t>& data, const std::vector<Section>& secs,
                                  uint32_t rva) {
    if (!rva) return {};
    std::vector<Import> imports;
    uint32_t desc = rva;
    for (;;) {
        auto raw = file_bytes(data, secs, desc, 20);
        uint32_t orig = load_le<uint32_t>(raw.data());
        uint32_t name_rva = load_le<uint32_t>(raw.data() + 12);
        uint32_t first = load_le<uint32_t>(raw.data() + 16);
        if (orig == 0 && name_rva == 0 && first == 0) break;
        std::string dll = cstring(data, secs, name_rva);
        uint32_t thunk = orig ? orig : first;
        uint32_t iat = first;
        for (;;) {
            uint64_t entry = u64(data, secs, thunk);
            if (entry == 0) break;
            Import item;
            item.dll = dll;
            item.iat_rva = iat;
            if (entry & kOrdinalFlag) {
                item.ordinal = static_cast<uint16_t>(entry & 0xFFFF);
            } else {
                item.name = cstring(data, secs, static_cast<uint32_t>((entry & 0x7FFFFFFF) + 2));
            }
            imports.push_back(item);
            thunk += 8;
            iat += 8;
        }
        desc += 20;
    }
    return imports;
}

std::vector<std::pair<uint32_t, int>> parse_relocs(const std::vector<uint8_t>& data,
                                                   const std::vector<Section>& secs, uint32_t rva,
                                                   uint32_t size) {
    if (!rva || !size) return {};
    std::vector<std::pair<uint32_t, int>> relocs;
    uint32_t consumed = 0;
    while (consumed + 8 <= size) {
        auto hdr = file_bytes(data, secs, rva + consumed, 8);
        uint32_t page = load_le<uint32_t>(hdr.data());
        uint32_t block = load_le<uint32_t>(hdr.data() + 4);
        if (block < 8) break;
        uint32_t count = (block - 8) / 2;
        auto entries = file_bytes(data, secs, rva + consumed + 8, count * 2);
        for (uint32_t i = 0; i < count; ++i) {
            uint16_t entry = load_le<uint16_t>(entries.data() + i * 2);
            int kind = entry >> 12;
            uint32_t off = entry & 0xFFF;
            if (kind == static_cast<int>(kRelDir64) || kind == static_cast<int>(kRelHighLow)) {
                relocs.emplace_back(page + off, kind);
            }
        }
        consumed += block;
    }
    return relocs;
}

} // namespace

void apply_relocs(std::vector<uint8_t>& buf, const std::vector<std::pair<uint32_t, int>>& relocs,
                  int64_t delta) {
    for (auto [rva, kind] : relocs) {
        if (kind == static_cast<int>(kRelDir64)) {
            if (rva + 8 > buf.size()) throw PayloadError("DIR64 reloc is outside the image");
            uint64_t value = load_le<uint64_t>(buf.data() + rva) + delta;
            store_le(buf.data() + rva, value);
        } else if (kind == static_cast<int>(kRelHighLow)) {
            if (rva + 4 > buf.size()) throw PayloadError("HIGHLOW reloc is outside the image");
            uint32_t value =
                load_le<uint32_t>(buf.data() + rva) + static_cast<uint32_t>(delta);
            store_le(buf.data() + rva, value);
        }
    }
}

std::vector<std::string> module_candidates(const std::string& dll) {
    std::string lower_dll = lower(dll);
    std::vector<std::string> names = {dll};
    if (lower_dll.rfind("api-ms-win-crt-", 0) == 0) {
        names.push_back("ucrtbase.dll");
        names.push_back("msvcrt.dll");
    }
    if (lower_dll.rfind("api-ms-win-core-", 0) == 0) {
        names.push_back("kernel32.dll");
        names.push_back("kernelbase.dll");
        names.push_back("ntdll.dll");
    }
    if (lower_dll == "vcruntime140.dll" || lower_dll == "vcruntime140_1.dll") {
        names.push_back("ntdll.dll");
    }
    std::vector<std::string> out;
    std::vector<std::string> seen;
    for (auto& name : names) {
        auto key = lower(name);
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
        seen.push_back(key);
        out.push_back(name);
    }
    return out;
}

PeImage PeImage::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw PayloadError("DLL not found: " + path);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
    return parse(std::move(data));
}

PeImage PeImage::parse(std::vector<uint8_t> data) {
    const uint64_t file_size = data.size();
    auto fits = [&](uint64_t off, uint64_t n) {
        return n <= file_size && off <= file_size - n;
    };
    if (data.size() < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        throw PayloadError("not a PE file (missing MZ)");
    }
    uint64_t e_lfanew = load_le<uint32_t>(data.data() + 0x3C);
    if (e_lfanew < 0x40 || !fits(e_lfanew, 4 + 20) || data[e_lfanew] != 'P' ||
        data[e_lfanew + 1] != 'E') {
        throw PayloadError("not a PE file (missing PE signature)");
    }
    uint64_t coff = e_lfanew + 4;
    uint16_t machine = load_le<uint16_t>(data.data() + coff);
    uint16_t nsec = load_le<uint16_t>(data.data() + coff + 2);
    uint16_t opt_size = load_le<uint16_t>(data.data() + coff + 16);
    if (machine != 0x8664) throw PayloadError("only AMD64 images are supported");
    uint64_t opt = coff + 20;
    if (opt_size < 112 || !fits(opt, opt_size)) {
        throw PayloadError("optional header is truncated");
    }
    uint16_t magic = load_le<uint16_t>(data.data() + opt);
    if (magic != 0x20B) throw PayloadError("only PE32+ is supported");
    uint32_t n_rva = load_le<uint32_t>(data.data() + opt + 108);
    if (n_rva > 32 || opt_size < 112ull + static_cast<uint64_t>(n_rva) * 8) {
        throw PayloadError("data directories do not fit the optional header");
    }
    auto directory = [&](uint32_t index, uint32_t* rva, uint32_t* size) {
        if (index >= n_rva) {
            *rva = 0;
            *size = 0;
            return;
        }
        uint64_t at = opt + 112 + static_cast<uint64_t>(index) * 8;
        *rva = load_le<uint32_t>(data.data() + at);
        *size = load_le<uint32_t>(data.data() + at + 4);
    };
    uint32_t export_rva = 0, export_size = 0, import_rva = 0, import_size = 0;
    uint32_t reloc_rva = 0, reloc_size = 0, tls_rva = 0, tls_size = 0;
    directory(0, &export_rva, &export_size);
    directory(1, &import_rva, &import_size);
    directory(5, &reloc_rva, &reloc_size);
    directory(9, &tls_rva, &tls_size);
    (void)import_size;
    (void)tls_rva;
    if (tls_size) throw PayloadError("TLS callbacks are not mapped");

    uint64_t sec_off = opt + opt_size;
    uint64_t sec_bytes = static_cast<uint64_t>(nsec) * 40;
    if (!fits(sec_off, sec_bytes)) throw PayloadError("section table is truncated");
    PeImage image;
    image.data = std::move(data);
    image.entry_rva = load_le<uint32_t>(image.data.data() + opt + 16);
    image.preferred_base = load_le<uint64_t>(image.data.data() + opt + 24);
    image.size_of_image = load_le<uint32_t>(image.data.data() + opt + 56);
    image.size_of_headers = load_le<uint32_t>(image.data.data() + opt + 60);
    for (uint16_t i = 0; i < nsec; ++i) {
        uint64_t off = sec_off + static_cast<uint64_t>(i) * 40;
        Section s;
        char name[9]{};
        std::memcpy(name, image.data.data() + off, 8);
        s.name = name;
        s.virtual_size = load_le<uint32_t>(image.data.data() + off + 8);
        s.va = load_le<uint32_t>(image.data.data() + off + 12);
        s.raw_size = load_le<uint32_t>(image.data.data() + off + 16);
        s.raw_ptr = load_le<uint32_t>(image.data.data() + off + 20);
        image.sections.push_back(s);
    }
    image.exports = parse_exports(image.data, image.sections, export_rva, export_size);
    image.imports = parse_imports(image.data, image.sections, import_rva);
    image.relocs = parse_relocs(image.data, image.sections, reloc_rva, reloc_size);
    return image;
}

std::vector<uint8_t> PeImage::mapped(uint64_t base) const {
    if (size_of_image == 0 || size_of_image > 0x10000000) {
        throw PayloadError("SizeOfImage is implausible");
    }
    std::vector<uint8_t> buf(size_of_image, 0);
    size_t hdr = (std::min)({static_cast<size_t>(size_of_headers), data.size(),
                             static_cast<size_t>(size_of_image)});
    std::memcpy(buf.data(), data.data(), hdr);
    for (auto& s : sections) {
        if (s.va >= size_of_image) continue;
        size_t n = (std::min)({static_cast<size_t>(s.raw_size), static_cast<size_t>(s.virtual_size),
                               static_cast<size_t>(size_of_image - s.va)});
        if (s.raw_ptr + n > data.size()) n = data.size() > s.raw_ptr ? data.size() - s.raw_ptr : 0;
        if (n) std::memcpy(buf.data() + s.va, data.data() + s.raw_ptr, n);
    }
    int64_t delta = static_cast<int64_t>(base - preferred_base);
    if (delta) apply_relocs(buf, relocs, delta);
    return buf;
}

std::optional<uint64_t> PeImage::entry_va(uint64_t base) const {
    if (!entry_rva) return std::nullopt;
    return base + entry_rva;
}

uint64_t PeImage::export_va(uint64_t base, const std::string& name) const {
    for (auto candidate : {name, name + "@1", "_" + name}) {
        auto it = exports.find(candidate);
        if (it != exports.end()) return base + it->second;
    }
    throw PayloadError("export is missing: " + name);
}

void write_image(Memory& mem, const Target& target, uint64_t base, std::span<const uint8_t> image) {
    write_process_va(mem, target.cr3, base, image, target.pid);
    auto mz = mem.read(base, 2, false, target.pid);
    if (mz.size() < 2 || mz[0] != 'M' || mz[1] != 'Z') {
        try {
            uint64_t pa = virt_to_phys(mem, target.cr3, base);
            mz = mem.read(pa, 2, true);
        } catch (...) {
        }
        if (mz.size() < 2 || mz[0] != 'M' || mz[1] != 'Z') {
            throw PayloadError("mapped image MZ check failed");
        }
    }
    LOG_INFO("wrote %d-byte image at 0x%llx", static_cast<int>(image.size()),
             static_cast<unsigned long long>(base));
}

void resolve_imports(Memory& mem, const Target& target, uint64_t base, const PeImage& pe) {
    for (auto& item : pe.imports) {
        if (!item.name) throw PayloadError("ordinal import is not supported");
        uint64_t addr = 0;
        std::exception_ptr last;
        for (auto& module : module_candidates(item.dll)) {
            try {
                addr = mem.export_addr(target.pid, lower(module), lower(*item.name));
                last = nullptr;
                break;
            } catch (...) {
                last = std::current_exception();
            }
        }
        if (!addr) {
            if (last) std::rethrow_exception(last);
            throw PayloadError("cannot resolve " + item.dll + "!" + *item.name);
        }
        uint8_t packed[8];
        store_le(packed, addr);
        write_process_va(mem, target.cr3, base + item.iat_rva, std::span<const uint8_t>(packed, 8),
                         target.pid);
    }
    LOG_INFO("resolved %d imports", static_cast<int>(pe.imports.size()));
}

} // namespace dma_hello
