// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/session.hpp"

#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include "vmmdll.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace dma_hello {
namespace {

constexpr uint32_t kPhysicalPid = 0xFFFFFFFFu;

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

void warn_if_symbol_files_missing() {
    HMODULE mod = GetModuleHandleA("vmm.dll");
    char path[MAX_PATH] = {};
    if (!mod || !GetModuleFileNameA(mod, path, MAX_PATH)) return;
    char* slash = strrchr(path, '\\');
    if (!slash) return;
    slash[1] = '\0';
    std::string dir = path;
    bool missing = false;
    for (const char* name : {"dbghelp.dll", "symsrv.dll"}) {
        if (GetFileAttributesA((dir + name).c_str()) == INVALID_FILE_ATTRIBUTES) {
            LOG_ERROR("missing %s next to vmm.dll in %s", name, dir.c_str());
            missing = true;
        }
    }
    if (missing) {
        LOG_ERROR("nt symbols stay unresolved until dbghelp.dll and symsrv.dll sit beside vmm.dll");
    }
}

} // namespace

Session::Session(const std::string& device) {
    warn_if_symbol_files_missing();
    std::string wait = "-waitinitialize";
    std::string devflag = "-device";
    std::string nopy = "-disable-python";
    std::string print = "-printf";
    LPCSTR argv[] = {devflag.c_str(), device.c_str(), wait.c_str(), nopy.c_str(), print.c_str()};
    handle_ = VMMDLL_Initialize(5, argv);
    if (!handle_) {
        throw SessionError("failed to open MemProcFS device " + device);
    }
    DWORD sys = 0;
    if (VMMDLL_PidGetFromName(handle_, "System", &sys) && sys) {
        kernel_pid_ = sys | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;
    } else {
        kernel_pid_ = 4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;
    }
    LOG_INFO("connected %s", device.c_str());
}

Session::~Session() {
    if (handle_) {
        VMMDLL_Close(handle_);
        handle_ = nullptr;
    }
}

uint32_t Session::resolve_pid(bool physical, uint32_t pid) const {
    if (physical) return kPhysicalPid;
    if (pid == 0) return kernel_pid_;
    return pid;
}

std::vector<uint8_t> Session::read(uint64_t address, size_t size, bool physical, uint32_t pid) {
    if (!handle_) throw SessionError("session is closed");
    if (size == 0) return {};
    std::vector<uint8_t> buf(size);
    DWORD got = 0;
    BOOL ok = VMMDLL_MemReadEx(handle_, resolve_pid(physical, pid), address, buf.data(),
                               static_cast<DWORD>(size), &got, VMMDLL_FLAG_NOCACHE);
    if (!ok || got != size) throw SessionError("read failed");
    return buf;
}

void Session::write(uint64_t address, std::span<const uint8_t> data, bool physical, uint32_t pid) {
    if (!handle_) throw SessionError("session is closed");
    if (data.empty()) return;
    if (!VMMDLL_MemWrite(handle_, resolve_pid(physical, pid), address,
                         const_cast<PBYTE>(data.data()), static_cast<DWORD>(data.size()))) {
        throw SessionError("write failed");
    }
}

std::optional<uint64_t> Session::virt2phys(uint64_t va, uint32_t pid) {
    if (!handle_) return std::nullopt;
    ULONG64 pa = 0;
    if (!VMMDLL_MemVirt2Phys(handle_, resolve_pid(false, pid), va, &pa) || !pa) return std::nullopt;
    return pa;
}

void Session::ensure_kernel_symbols() {
    if (kernel_symbols_checked_ || !handle_) return;
    kernel_symbols_checked_ = true;
    uint32_t pid = kernel_pid_ & ~VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;
    ULONG64 base = 0;
    const char* found = nullptr;
    for (const char* name : {"ntoskrnl.exe", "ntkrnlmp.exe"}) {
        base = VMMDLL_ProcessGetModuleBaseU(handle_, pid, name);
        if (base) {
            found = name;
            break;
        }
    }
    char module[MAX_PATH] = {};
    if (base && VMMDLL_PdbLoad(handle_, pid, base, module) && module[0]) {
        LOG_INFO("kernel pdb %s base=0x%llx module=%s", found, static_cast<unsigned long long>(base),
                 module);
        return;
    }
    LOG_ERROR("kernel pdb did not load (module=%s base=0x%llx). The analysis PC needs "
              "dbghelp.dll and symsrv.dll beside vmm.dll and a path to the Microsoft symbol server.",
              found ? found : "ntoskrnl.exe", static_cast<unsigned long long>(base));
}

std::optional<uint64_t> Session::symbol(const char* name) {
    ensure_kernel_symbols();
    std::string key = name ? name : "";
    auto it = symbol_cache_.find(key);
    if (it != symbol_cache_.end()) return it->second;
    ULONG64 va = 0;
    std::optional<uint64_t> out;
    if (handle_ && VMMDLL_PdbSymbolAddress(handle_, "nt", name, &va) && va) out = va;
    symbol_cache_[key] = out;
    return out;
}

std::optional<int> Session::type_size(const char* type) {
    ensure_kernel_symbols();
    std::string key = type ? type : "";
    auto it = size_cache_.find(key);
    if (it != size_cache_.end()) return it->second;
    DWORD size = 0;
    std::optional<int> out;
    if (handle_ && VMMDLL_PdbTypeSize(handle_, "nt", type, &size) && size > 0) {
        out = static_cast<int>(size);
    }
    size_cache_[key] = out;
    return out;
}

std::optional<int> Session::field_offset(const char* type, const char* field) {
    ensure_kernel_symbols();
    std::string key = std::string(type ? type : "") + "|" + (field ? field : "");
    auto it = field_cache_.find(key);
    if (it != field_cache_.end()) return it->second;
    DWORD off = 0;
    std::optional<int> out;
    if (handle_ && VMMDLL_PdbTypeChildOffset(handle_, "nt", type, field, &off)) {
        out = static_cast<int>(off);
    }
    field_cache_[key] = out;
    return out;
}

ProcessInfo Session::find_process(const std::string& name) {
    if (!handle_) throw SessionError("session is closed");
    DWORD pid = 0;
    if (!VMMDLL_PidGetFromName(handle_, name.c_str(), &pid) || !pid) {
        throw ProcessNotFound(name + " is not running on the target");
    }
    VMMDLL_PROCESS_INFORMATION info{};
    SIZE_T cb = sizeof(info);
    info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    if (!VMMDLL_ProcessGetInformation(handle_, pid, &info, &cb)) {
        throw SessionError("ProcessGetInformation failed for " + name);
    }
    if (!info.paDTB) throw SessionError(name + ": DirectoryTableBase is 0");
    ProcessInfo t;
    t.name = name;
    t.pid = pid;
    t.eprocess = info.win.vaEPROCESS;
    t.cr3 = info.paDTB;
    LOG_INFO("target %s pid=%u eprocess=0x%llx cr3=0x%llx", name.c_str(), pid,
             static_cast<unsigned long long>(t.eprocess), static_cast<unsigned long long>(t.cr3));
    return t;
}

uint64_t Session::export_addr(uint32_t pid, const std::string& module, const std::string& name) {
    ULONG64 va = VMMDLL_ProcessGetProcAddressU(handle_, pid, module.c_str(), name.c_str());
    if (!va) throw SessionError(module + "!" + name + " is not in the target");
    return va;
}

std::vector<std::pair<uint64_t, uint64_t>> Session::vad_map(uint32_t pid) {
    PVMMDLL_MAP_VAD map = nullptr;
    if (!VMMDLL_Map_GetVadU(handle_, pid, TRUE, &map) || !map) {
        throw AllocationError("process VAD map failed");
    }
    std::vector<std::pair<uint64_t, uint64_t>> out;
    for (DWORD i = 0; i < map->cMap; ++i) {
        out.emplace_back(map->pMap[i].vaStart, map->pMap[i].vaEnd);
    }
    VMMDLL_MemFree(map);
    return out;
}

std::vector<std::pair<uint64_t, uint64_t>> Session::phys_map() {
    PVMMDLL_MAP_PHYSMEM map = nullptr;
    if (!VMMDLL_Map_GetPhysMem(handle_, &map) || !map) {
        throw SessionError("physical memory map unavailable");
    }
    std::vector<std::pair<uint64_t, uint64_t>> out;
    for (DWORD i = 0; i < map->cMap; ++i) {
        out.emplace_back(map->pMap[i].pa, map->pMap[i].cb);
    }
    VMMDLL_MemFree(map);
    if (out.empty()) throw SessionError("physical memory map is empty");
    return out;
}

std::unordered_map<uint64_t, std::string> Session::pfn_types(const std::vector<uint64_t>& pfns) {
    std::unordered_map<uint64_t, std::string> out;
    if (pfns.empty()) return out;
    std::vector<DWORD> ids;
    ids.reserve(pfns.size());
    for (auto p : pfns) ids.push_back(static_cast<DWORD>(p));
    PVMMDLL_MAP_PFN map = nullptr;
    if (!VMMDLL_Map_GetPfnEx(handle_, ids.data(), static_cast<DWORD>(ids.size()), &map, 0) ||
        !map) {
        return out;
    }
    for (DWORD i = 0; i < map->cMap; ++i) {
        auto& e = map->pMap[i];
        const char* tp = "Other";
        switch (e.PageLocation) {
        case VmmDll_PfnTypeZero:
            tp = "Zeroed";
            break;
        case VmmDll_PfnTypeFree:
            tp = "Free";
            break;
        default:
            break;
        }
        out[e.dwPfn] = tp;
    }
    VMMDLL_MemFree(map);
    return out;
}

} // namespace dma_hello
