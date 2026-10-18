// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/inject.hpp"

#include "dma_hello/error.hpp"
#include "dma_hello/log.hpp"
#include "dma_hello/mm/allocate.hpp"
#include "dma_hello/mm/constants.hpp"
#include "dma_hello/mm/pfn.hpp"
#include "dma_hello/session.hpp"

#include <algorithm>
#include <filesystem>

namespace dma_hello {

InjectResult run(const Settings& settings) {
    if (!std::filesystem::is_regular_file(settings.dll_path)) {
        throw PayloadError("DLL not found: " + settings.dll_path);
    }
    auto pe = PeImage::load(settings.dll_path);
    uint64_t need = (std::max)(settings.alloc_size,
                               static_cast<uint64_t>((pe.size_of_image + kPageSize * 2 + 0xFFF) &
                                                     ~0xFFFull));
    LOG_INFO("image size=0x%x preferred=0x%llx exports=%d imports=%d", pe.size_of_image,
             static_cast<unsigned long long>(pe.preferred_base), static_cast<int>(pe.exports.size()),
             static_cast<int>(pe.imports.size()));

    Session session(settings.device);
    auto target = find_process(session, settings.process);
    auto allocation = allocate(session, target, need, settings.protection);
    try {
        auto mapped = pe.mapped(allocation.va);
        write_image(session, target, allocation.va, mapped);
        resolve_imports(session, target, allocation.va, pe);
        auto hook = install_hook(session, target, allocation, pe, settings.hook_module,
                                 settings.hook_function, settings.hook_export);
        return InjectResult{target, std::move(allocation), std::move(pe), hook};
    } catch (...) {
        retain_claim(allocation.pages);
        throw;
    }
}

} // namespace dma_hello
