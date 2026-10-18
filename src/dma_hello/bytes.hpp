// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace dma_hello {

template <typename T>
inline T load_le(const uint8_t* p) {
    T v{};
    std::memcpy(&v, p, sizeof(T));
    return v;
}

template <typename T>
inline T load_le(std::span<const uint8_t> s, size_t off = 0) {
    return load_le<T>(s.data() + off);
}

template <typename T>
inline void store_le(uint8_t* p, T v) {
    std::memcpy(p, &v, sizeof(T));
}

template <typename T>
inline void store_le(std::vector<uint8_t>& buf, size_t off, T v) {
    store_le<T>(buf.data() + off, v);
}

inline void append_bytes(std::vector<uint8_t>& out, std::span<const uint8_t> b) {
    out.insert(out.end(), b.begin(), b.end());
}

inline void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    uint8_t b[8];
    store_le(b, v);
    out.insert(out.end(), b, b + 8);
}

inline void append_i32(std::vector<uint8_t>& out, int32_t v) {
    uint8_t b[4];
    store_le(b, v);
    out.insert(out.end(), b, b + 4);
}

inline std::vector<uint8_t> hex_bytes(const char* hex) {
    std::vector<uint8_t> out;
    unsigned v = 0;
    int nibble = 0;
    for (const char* p = hex; *p; ++p) {
        char c = *p;
        if (c == ' ' || c == '\t') continue;
        unsigned d = 0;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else continue;
        v = (v << 4) | d;
        if (++nibble == 2) {
            out.push_back(static_cast<uint8_t>(v));
            v = 0;
            nibble = 0;
        }
    }
    return out;
}

} // namespace dma_hello
