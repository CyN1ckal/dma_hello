// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "catch_amalgamated.hpp"
#include "dma_hello/memory.hpp"
#include "dma_hello/pe.hpp"

#include <algorithm>
#include <cstring>
#include <string>

using namespace dma_hello;

static std::vector<uint8_t> minimal_pe() {
    std::vector<uint8_t> buf(0x600, 0);
    buf[0] = 'M';
    buf[1] = 'Z';
    store_le(buf.data() + 0x3C, uint32_t{0x80});
    buf[0x80] = 'P';
    buf[0x81] = 'E';
    store_le(buf.data() + 0x84, uint16_t{0x8664});
    store_le(buf.data() + 0x86, uint16_t{1});
    store_le(buf.data() + 0x94, uint16_t{0xF0});
    store_le(buf.data() + 0x96, uint16_t{0x22});
    uint32_t opt = 0x84 + 20;
    store_le(buf.data() + opt, uint16_t{0x20B});
    store_le(buf.data() + opt + 16, uint32_t{0x1000});
    store_le(buf.data() + opt + 24, uint64_t{0x140000000});
    store_le(buf.data() + opt + 56, uint32_t{0x2000});
    store_le(buf.data() + opt + 60, uint32_t{0x400});
    store_le(buf.data() + opt + 108, uint32_t{16});
    uint32_t dd = opt + 112;
    store_le(buf.data() + dd + 0, uint32_t{0x1080});
    store_le(buf.data() + dd + 4, uint32_t{0x80});
    store_le(buf.data() + dd + 8, uint32_t{0x1100});
    store_le(buf.data() + dd + 12, uint32_t{0x40});
    store_le(buf.data() + dd + 40, uint32_t{0x1180});
    store_le(buf.data() + dd + 44, uint32_t{0x0C});
    uint32_t sec = opt + 0xF0;
    std::memcpy(buf.data() + sec, ".text", 5);
    store_le(buf.data() + sec + 8, uint32_t{0x200});
    store_le(buf.data() + sec + 12, uint32_t{0x1000});
    store_le(buf.data() + sec + 16, uint32_t{0x200});
    store_le(buf.data() + sec + 20, uint32_t{0x400});
    uint32_t text_off = 0x400;
    store_le(buf.data() + text_off, uint64_t{0x140000000});
    uint32_t ed = text_off + 0x80;
    store_le(buf.data() + ed + 20, uint32_t{1});
    store_le(buf.data() + ed + 24, uint32_t{1});
    store_le(buf.data() + ed + 28, uint32_t{1});
    uint32_t funcs_rva = 0x1080 + 40;
    uint32_t names_rva = funcs_rva + 4;
    uint32_t ords_rva = names_rva + 4;
    uint32_t name_rva = ords_rva + 2;
    store_le(buf.data() + ed + 28, funcs_rva);
    store_le(buf.data() + ed + 32, names_rva);
    store_le(buf.data() + ed + 36, ords_rva);
    store_le(buf.data() + text_off + (funcs_rva - 0x1000), uint32_t{0x1008});
    store_le(buf.data() + text_off + (names_rva - 0x1000), name_rva);
    store_le(buf.data() + text_off + (ords_rva - 0x1000), uint16_t{0});
    const char* export_name = "LaunchHello";
    uint32_t name_off = text_off + (name_rva - 0x1000);
    std::memcpy(buf.data() + name_off, export_name, 12);
    uint32_t rel = text_off + 0x180;
    store_le(buf.data() + rel, uint32_t{0x1000});
    store_le(buf.data() + rel + 4, uint32_t{12});
    store_le(buf.data() + rel + 8, uint16_t{(10 << 12) | 0});
    return buf;
}

TEST_CASE("parse and relocate pe") {
    auto pe = PeImage::parse(minimal_pe());
    REQUIRE(pe.preferred_base == 0x140000000ull);
    REQUIRE(pe.entry_rva == 0x1000);
    REQUIRE(pe.exports.count("LaunchHello"));
    auto mapped = pe.mapped(0x100000000ull);
    REQUIRE(load_le<uint64_t>(mapped.data() + 0x1000) == 0x100000000ull);
    REQUIRE(pe.export_va(0x100000000ull, "LaunchHello") == 0x100000000ull + 0x1008);
}

TEST_CASE("api-set and vcruntime candidates") {
    auto names = module_candidates("api-ms-win-crt-runtime-l1-1-0.dll");
    REQUIRE(std::find(names.begin(), names.end(), "ucrtbase.dll") != names.end());
    REQUIRE(names[0] == "api-ms-win-crt-runtime-l1-1-0.dll");
    auto vcr = module_candidates("vcruntime140.dll");
    REQUIRE(std::find(vcr.begin(), vcr.end(), "ntdll.dll") != vcr.end());
}

TEST_CASE("export directory uses AddressOfFunctions") {
    auto buf = minimal_pe();
    uint32_t text_off = 0x400;
    uint32_t ed = text_off + 0x80;
    store_le(buf.data() + ed + 16, uint32_t{99});
    auto pe = PeImage::parse(std::move(buf));
    REQUIRE(pe.exports.count("LaunchHello"));
    REQUIRE(pe.export_va(0x100000000ull, "LaunchHello") == 0x100000000ull + 0x1008);
}

TEST_CASE("import lookup is case-insensitive") {
    class Rec : public Memory {
    public:
        std::string module;
        std::string name;
        std::vector<uint8_t> read(uint64_t, size_t size, bool, uint32_t) override {
            return std::vector<uint8_t>(size, 0);
        }
        void write(uint64_t, std::span<const uint8_t>, bool, uint32_t) override {}
        uint64_t export_addr(uint32_t, const std::string& mod, const std::string& fn) override {
            module = mod;
            name = fn;
            return 0x99;
        }
    } mem;
    PeImage pe;
    Import item;
    item.dll = "USER32.DLL";
    item.name = "MessageBoxA";
    item.iat_rva = 0x1000;
    pe.imports.push_back(item);
    Target target;
    target.pid = 1;
    resolve_imports(mem, target, 0x20000, pe);
    REQUIRE(mem.module == "user32.dll");
    REQUIRE(mem.name == "messageboxa");
}

TEST_CASE("truncated pe is rejected") {
    auto short_header = minimal_pe();
    short_header.resize(0x90);
    REQUIRE_THROWS_AS(PeImage::parse(std::move(short_header)), PayloadError);

    std::vector<uint8_t> wrapped(0x40, 0);
    wrapped[0] = 'M';
    wrapped[1] = 'Z';
    store_le(wrapped.data() + 0x3C, uint32_t{0xFFFFFFF0u});
    REQUIRE_THROWS_AS(PeImage::parse(std::move(wrapped)), PayloadError);

    auto no_sections = minimal_pe();
    no_sections.resize(0x190);
    REQUIRE_THROWS_AS(PeImage::parse(std::move(no_sections)), PayloadError);
}

TEST_CASE("dir64 reloc") {
    std::vector<uint8_t> buf(16, 0);
    store_le(buf.data(), uint64_t{0x140000000});
    apply_relocs(buf, {{0, 10}}, static_cast<int64_t>(0x100000000ull - 0x140000000ull));
    REQUIRE(load_le<uint64_t>(buf.data()) == 0x100000000ull);
}
