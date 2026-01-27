#pragma once

#include <cstdint>
#include <string>

namespace ghostfs {

  struct BenchmarkConfig {
    std::string dir;                     // Directory to benchmark
    uint32_t small_file_count = 1000;    // Number of small files
    uint32_t small_file_size = 4096;     // Size of each small file (bytes)
    uint32_t large_file_size_mb = 1000;  // Size of large file (MB)
    uint8_t parallel_jobs = 8;           // Parallel jobs for small files
    bool verify = true;                  // Verify data integrity
  };

  struct BenchmarkResults {
    // Small files
    double small_write_ms = 0;
    double small_read_ms = 0;
    double small_write_fps = 0;  // files per second
    double small_read_fps = 0;

    // Large file
    double large_write_ms = 0;
    double large_read_ms = 0;
    double large_write_mbps = 0;  // MB per second
    double large_read_mbps = 0;

    // Verification
    bool integrity_passed = false;
  };

  // Run the benchmark suite
  int run_benchmark(const BenchmarkConfig& config);

  void NewFunction();

  void NewFunction();

  void NewFunction();

}  // namespace ghostfs
