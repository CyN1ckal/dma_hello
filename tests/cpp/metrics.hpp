// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace dma_hello {
namespace test {

// Counters a test can write after a simulated run. write_to emits pfn-metrics.csv
// and timeline.log so a run can be checked without scraping the console.
struct RunMetrics {
    int pfn_ok = 0;
    int pfn_attempts = 0;
    int vad_ok = 0;
    int vad_attempts = 0;
    int hook_ok = 0;
    int hook_attempts = 0;
    int verify_ok = 0;
    int verify_attempts = 0;
    std::vector<std::string> events;

    void note(const std::string& text) { events.push_back(text); }

    void write_to(const std::filesystem::path& dir) const {
        std::filesystem::create_directories(dir);
        std::ofstream csv(dir / "pfn-metrics.csv");
        csv << "metric,success,attempts\n";
        csv << "pfn_claim," << pfn_ok << "," << pfn_attempts << "\n";
        csv << "vad_extension," << vad_ok << "," << vad_attempts << "\n";
        csv << "hook," << hook_ok << "," << hook_attempts << "\n";
        csv << "write_verify," << verify_ok << "," << verify_attempts << "\n";
        std::ofstream log(dir / "timeline.log");
        for (size_t i = 0; i < events.size(); ++i) log << i << " " << events[i] << "\n";
    }
};

} // namespace test
} // namespace dma_hello
