// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <stdexcept>
#include <string>

namespace dma_hello {

class DmaError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Device open failed, or a read or write was rejected by the session.
class SessionError : public DmaError {
public:
    using DmaError::DmaError;
};

// find_process did not see the named image.
class ProcessNotFound : public DmaError {
public:
    using DmaError::DmaError;
};

// The VA was chosen, but the allocation cannot be finished.
class AllocationError : public DmaError {
public:
    using DmaError::DmaError;
};

// The PFN claim was refused, or the free list could not be edited safely.
class PfnError : public AllocationError {
public:
    using AllocationError::AllocationError;
};

// The free-list edit was applied and the restore write did not land.
// Callers must not continue claiming pages after this.
class PfnRollbackError : public PfnError {
public:
    using PfnError::PfnError;
};

// The page-table walk failed, or a PTE could not be programmed.
class MappingError : public AllocationError {
public:
    using AllocationError::AllocationError;
};

// The payload file is missing, or the PE cannot be mapped or relocated.
class PayloadError : public DmaError {
public:
    using DmaError::DmaError;
};

// The hook target was refused, or the stub could not be installed.
class HookError : public DmaError {
public:
    using DmaError::DmaError;
};

} // namespace dma_hello
