// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdarg>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>

namespace dma_hello {

enum class LogLevel { Crit = 0, Error = 1, Warn = 2, Info = 3, Debug = 4 };

void setup_log(int level, const std::string& file);
void log_write(LogLevel level, const char* tag, const char* fmt, ...);

#define LOG_INFO(...) ::dma_hello::log_write(::dma_hello::LogLevel::Info, "dma", __VA_ARGS__)
#define LOG_WARN(...) ::dma_hello::log_write(::dma_hello::LogLevel::Warn, "dma", __VA_ARGS__)
#define LOG_ERROR(...) ::dma_hello::log_write(::dma_hello::LogLevel::Error, "dma", __VA_ARGS__)
#define LOG_DEBUG(...) ::dma_hello::log_write(::dma_hello::LogLevel::Debug, "dma", __VA_ARGS__)

} // namespace dma_hello
