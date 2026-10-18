// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#include "dma_hello/log.hpp"

#include "dma_hello/error.hpp"

#include <chrono>
#include <ctime>

namespace dma_hello {
namespace {

LogLevel g_level = LogLevel::Info;
std::mutex g_mu;
FILE* g_file = nullptr;

const char* name(LogLevel l) {
    switch (l) {
    case LogLevel::Crit: return "CRIT ";
    case LogLevel::Error: return "ERROR";
    case LogLevel::Warn: return "WARN ";
    case LogLevel::Info: return "INFO ";
    case LogLevel::Debug: return "DEBUG";
    }
    return "INFO ";
}

} // namespace

void setup_log(int level, const std::string& file) {
    std::lock_guard lock(g_mu);
    if (level <= 0) g_level = LogLevel::Crit;
    else if (level == 1) g_level = LogLevel::Error;
    else if (level == 2) g_level = LogLevel::Warn;
    else if (level == 3) g_level = LogLevel::Info;
    else g_level = LogLevel::Debug;
    if (g_file && g_file != stderr) {
        fclose(g_file);
        g_file = nullptr;
    }
    if (!file.empty()) {
        g_file = fopen(file.c_str(), "a");
        if (!g_file) {
            std::fprintf(stderr, "cannot open log file %s\n", file.c_str());
            throw SessionError("cannot open log file " + file);
        }
    }
}

void log_write(LogLevel level, const char* tag, const char* fmt, ...) {
    if (static_cast<int>(level) > static_cast<int>(g_level)) return;
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch())
                  .count() %
              1000;
    std::tm tm{};
    localtime_s(&tm, &t);

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "[%02d:%02d:%02d.%03d] %s %s: ",
             tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms), name(level),
             tag ? tag : "dma");

    char body[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    std::lock_guard lock(g_mu);
    fputs(prefix, stderr);
    fputs(body, stderr);
    fputc('\n', stderr);
    if (g_file) {
        fputs(prefix, g_file);
        fputs(body, g_file);
        fputc('\n', g_file);
        fflush(g_file);
    }
}

} // namespace dma_hello
