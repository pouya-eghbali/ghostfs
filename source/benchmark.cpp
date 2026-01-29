#include <fmt/format.h>
#include <ghostfs/benchmark.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>
#include <vector>

#ifdef __APPLE__
#  include <CommonCrypto/CommonDigest.h>
#else
#  include <openssl/evp.h>
#endif

namespace ghostfs {

  namespace fs = std::filesystem;

  // ============================================================================
  // Terminal Colors and Formatting
  // ============================================================================

  namespace term {

    constexpr const char* RESET = "\033[0m";
    constexpr const char* BOLD = "\033[1m";
    constexpr const char* DIM = "\033[2m";

    constexpr const char* RED = "\033[31m";
    constexpr const char* GREEN = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* CYAN = "\033[36m";

    constexpr const char* HIDE_CURSOR = "\033[?25l";
    constexpr const char* SHOW_CURSOR = "\033[?25h";
    constexpr const char* CLEAR_LINE = "\033[2K\r";

    inline bool supports_color() {
      const char* term = std::getenv("TERM");
      if (!term) return false;
      std::string t(term);
      return t.find("color") != std::string::npos || t.find("xterm") != std::string::npos
             || t.find("screen") != std::string::npos || t.find("tmux") != std::string::npos
             || t == "linux";
    }

    static bool use_color = supports_color();

    inline std::string color(const char* c, const std::string& text) {
      if (!use_color) return text;
      return std::string(c) + text + RESET;
    }

    inline std::string bold(const std::string& text) { return color(BOLD, text); }
    inline std::string dim(const std::string& text) { return color(DIM, text); }
    inline std::string red(const std::string& text) { return color(RED, text); }
    inline std::string green(const std::string& text) { return color(GREEN, text); }
    inline std::string yellow(const std::string& text) { return color(YELLOW, text); }
    inline std::string cyan(const std::string& text) { return color(CYAN, text); }

  }  // namespace term

  // ============================================================================
  // Spinner
  // ============================================================================

  class Spinner {
  public:
    Spinner(const std::string& message) : message_(message), running_(false) {}
    ~Spinner() { stop(); }

    void start() {
      running_ = true;
      if (term::use_color) {
        std::cout << term::HIDE_CURSOR << std::flush;
      }
      thread_ = std::thread([this]() {
        const std::vector<std::string> frames = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        size_t frame = 0;
        while (running_) {
          {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << term::CLEAR_LINE << term::cyan(frames[frame]) << " " << message_
                      << std::flush;
          }
          frame = (frame + 1) % frames.size();
          std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
      });
    }

    void stop(bool success = true) {
      if (!running_) return;
      running_ = false;
      if (thread_.joinable()) thread_.join();
      std::cout << term::CLEAR_LINE;
      if (term::use_color) std::cout << term::SHOW_CURSOR;
      if (success) {
        std::cout << term::green("✓") << " " << message_ << std::endl;
      } else {
        std::cout << term::red("✗") << " " << message_ << std::endl;
      }
    }

    void stop_with_result(const std::string& result) {
      if (!running_) return;
      running_ = false;
      if (thread_.joinable()) thread_.join();
      std::cout << term::CLEAR_LINE;
      if (term::use_color) std::cout << term::SHOW_CURSOR;
      std::cout << term::green("✓") << " " << message_ << " " << term::dim("→") << " "
                << term::bold(result) << std::endl;
    }

  private:
    std::string message_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::mutex mutex_;
  };

  // ============================================================================
  // Utilities
  // ============================================================================

  class Timer {
  public:
    void start() { start_ = std::chrono::high_resolution_clock::now(); }
    double elapsed_ms() const {
      auto end = std::chrono::high_resolution_clock::now();
      return std::chrono::duration<double, std::milli>(end - start_).count();
    }

  private:
    std::chrono::high_resolution_clock::time_point start_;
  };

  std::string format_size(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 4) {
      size /= 1024;
      unit++;
    }
    if (unit == 0) return fmt::format("{} {}", static_cast<int>(size), units[unit]);
    return fmt::format("{:.1f} {}", size, units[unit]);
  }

  std::string format_duration(double ms) {
    if (ms < 1000) return fmt::format("{:.0f}ms", ms);
    if (ms < 60000) return fmt::format("{:.2f}s", ms / 1000);
    return fmt::format("{:.1f}m", ms / 60000);
  }

  std::string sha256_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

#ifdef __APPLE__
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
      CC_SHA256_Update(&ctx, buffer, static_cast<CC_LONG>(file.gcount()));
    }

    unsigned char hash[32];
    CC_SHA256_Final(hash, &ctx);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
      EVP_DigestUpdate(ctx, buffer, file.gcount());
    }

    unsigned char hash[32];
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
#endif

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
      ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
  }

  std::vector<char> generate_random_data(size_t size) {
    std::vector<char> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < size; i++) {
      data[i] = static_cast<char>(dis(gen));
    }
    return data;
  }

  // Drop kernel page cache to ensure cold reads (Linux only)
  void drop_caches() {
#ifdef __linux__
    sync();
    std::ofstream drop("/proc/sys/vm/drop_caches");
    if (drop) {
      drop << "3";
      drop.close();
    }
#endif
  }

  // ============================================================================
  // Benchmark Implementation
  // ============================================================================

  void print_header(const BenchmarkConfig& config) {
    std::cout << std::endl;
    std::cout << term::bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
              << std::endl;
    std::cout << term::bold(term::cyan("  GhostFS Benchmark Suite")) << std::endl;
    std::cout << term::bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
              << std::endl;
    std::cout << std::endl;

    std::cout << term::dim("  Configuration:") << std::endl;
    std::cout << "    Directory:     " << term::yellow(config.dir) << std::endl;
    std::cout << "    Small files:   " << term::yellow(std::to_string(config.small_file_count))
              << " x " << term::yellow(format_size(config.small_file_size)) << std::endl;
    std::cout << "    Large file:    " << term::yellow(std::to_string(config.large_file_size_mb))
              << " MB" << std::endl;
    std::cout << "    Parallel jobs: " << term::yellow(std::to_string(config.parallel_jobs))
              << std::endl;
    std::cout << std::endl;
  }

  void print_results_table(const BenchmarkConfig& config, const BenchmarkResults& results) {
    std::cout << std::endl;
    std::cout << term::bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
              << std::endl;
    std::cout << term::bold(term::cyan("  Results")) << std::endl;
    std::cout << term::bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
              << std::endl;
    std::cout << std::endl;

    std::cout << "  "
              << term::bold(fmt::format("{:<24} {:>12} {:>14}", "Test", "Time", "Throughput"))
              << std::endl;
    std::cout << "  " << term::dim("────────────────────────────────────────────────────")
              << std::endl;

    std::string small_desc = fmt::format("Small files ({} x {})", config.small_file_count,
                                         format_size(config.small_file_size));
    std::cout << "  " << fmt::format("{:<24}", small_desc) << std::endl;
    std::cout << "    "
              << fmt::format("{:<22} {:>12} {:>14}", "Write",
                             format_duration(results.small_write_ms),
                             fmt::format("{:.1f} files/s", results.small_write_fps))
              << std::endl;
    std::cout << "    "
              << fmt::format("{:<22} {:>12} {:>14}", "Read", format_duration(results.small_read_ms),
                             fmt::format("{:.1f} files/s", results.small_read_fps))
              << std::endl;

    std::string large_desc = fmt::format("Large file ({} MB)", config.large_file_size_mb);
    std::cout << "  " << fmt::format("{:<24}", large_desc) << std::endl;
    std::cout << "    "
              << fmt::format("{:<22} {:>12} {:>14}", "Write",
                             format_duration(results.large_write_ms),
                             fmt::format("{:.1f} MB/s", results.large_write_mbps))
              << std::endl;
    std::cout << "    "
              << fmt::format("{:<22} {:>12} {:>14}", "Read", format_duration(results.large_read_ms),
                             fmt::format("{:.1f} MB/s", results.large_read_mbps))
              << std::endl;

    std::cout << std::endl;
    std::cout << "  " << term::dim("────────────────────────────────────────────────────")
              << std::endl;

    std::cout << "  " << fmt::format("{:<24}", "Data integrity");
    if (results.integrity_passed) {
      std::cout << term::green(term::bold("PASSED")) << std::endl;
    } else {
      std::cout << term::red(term::bold("FAILED")) << std::endl;
    }

    std::cout << std::endl;
    std::cout << term::bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
              << std::endl;
    std::cout << std::endl;
  }

  int run_benchmark(const BenchmarkConfig& config) {
    BenchmarkResults results;

    if (config.write_only && config.read_only) {
      std::cerr << term::red("Error:") << " Cannot specify both --write-only and --read-only"
                << std::endl;
      return 1;
    }

    if (!fs::exists(config.dir)) {
      std::cerr << term::red("Error:") << " Directory does not exist: " << config.dir << std::endl;
      return 1;
    }

    if (!fs::is_directory(config.dir)) {
      std::cerr << term::red("Error:") << " Path is not a directory: " << config.dir << std::endl;
      return 1;
    }

    print_header(config);

    std::string tmp_base = "/tmp/ghostfs-benchmark-" + std::to_string(std::time(nullptr));
    std::string tmp_data = tmp_base + "/data";
    std::string tmp_small = tmp_data + "/small";
    std::string bench_dir = config.dir + "/ghostfs-bench";

    fs::create_directories(tmp_small);
    if (!config.read_only) {
      fs::create_directories(bench_dir);
    }

    // For write_only: keep bench_dir for subsequent read_only run
    // For read_only: assume bench_dir already exists from write_only run
    auto cleanup = [&]() {
      fs::remove_all(tmp_base);
      if (!config.write_only) {
        fs::remove_all(bench_dir);
      }
    };

    Timer timer;

    // Step 1: Generate test data
    {
      Spinner spinner("Generating test data");
      spinner.start();

      auto small_data = generate_random_data(config.small_file_size);
      for (uint32_t i = 0; i < config.small_file_count; i++) {
        std::string path = tmp_small + "/file_" + std::to_string(i) + ".dat";
        std::ofstream file(path, std::ios::binary);
        file.write(small_data.data(), static_cast<std::streamsize>(small_data.size()));
      }

      std::string large_path = tmp_data + "/large.bin";
      std::ofstream large_file(large_path, std::ios::binary);
      auto chunk = generate_random_data(1024 * 1024);
      for (uint32_t i = 0; i < config.large_file_size_mb; i++) {
        large_file.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
      }
      large_file.close();

      uint64_t total_data
          = (static_cast<uint64_t>(config.small_file_count) * config.small_file_size)
            + (static_cast<uint64_t>(config.large_file_size_mb) * 1024 * 1024);
      spinner.stop_with_result(format_size(total_data) + " generated");
    }

    std::cout << std::endl;
    std::cout << term::dim("  Running benchmarks...") << std::endl;
    std::cout << std::endl;

    // Step 2: Small files write
    if (!config.read_only) {
      Spinner spinner("Small files: writing");
      spinner.start();

      std::string bench_small = bench_dir + "/small";
      fs::create_directories(bench_small);

      timer.start();

      std::vector<std::thread> threads;
      std::atomic<uint32_t> file_index{0};

      for (uint8_t t = 0; t < config.parallel_jobs; t++) {
        threads.emplace_back([&]() {
          while (true) {
            uint32_t i = file_index.fetch_add(1);
            if (i >= config.small_file_count) break;

            std::string src = tmp_small + "/file_" + std::to_string(i) + ".dat";
            std::string dst = bench_small + "/file_" + std::to_string(i) + ".dat";

            std::ifstream in(src, std::ios::binary);
            std::ofstream out(dst, std::ios::binary);
            out << in.rdbuf();
          }
        });
      }

      for (auto& t : threads) t.join();

      sync();

      results.small_write_ms = timer.elapsed_ms();
      results.small_write_fps = (config.small_file_count * 1000.0) / results.small_write_ms;

      spinner.stop_with_result(fmt::format("{:.1f} files/s", results.small_write_fps));
    }

    // Run pre-read command if specified (e.g., restart MinIO to clear S3 cache)
    if (!config.write_only && !config.pre_read_cmd.empty()) {
      Spinner spinner("Running pre-read command");
      spinner.start();
      int ret = std::system(config.pre_read_cmd.c_str());
      spinner.stop(ret == 0);
    }

    // Step 3: Small files read
    if (!config.write_only) {
      Spinner spinner("Small files: reading");
      spinner.start();

      std::string bench_small = bench_dir + "/small";

      // Drop kernel page cache for cold read test
      drop_caches();

      timer.start();

      std::vector<std::thread> threads;
      std::atomic<uint32_t> file_index{0};

      for (uint8_t t = 0; t < config.parallel_jobs; t++) {
        threads.emplace_back([&]() {
          std::vector<char> buffer(config.small_file_size);
          while (true) {
            uint32_t i = file_index.fetch_add(1);
            if (i >= config.small_file_count) break;

            std::string path = bench_small + "/file_" + std::to_string(i) + ".dat";
            std::ifstream file(path, std::ios::binary);
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
          }
        });
      }

      for (auto& t : threads) t.join();

      results.small_read_ms = timer.elapsed_ms();
      results.small_read_fps = (config.small_file_count * 1000.0) / results.small_read_ms;

      spinner.stop_with_result(fmt::format("{:.1f} files/s", results.small_read_fps));
    }

    // Step 4: Large file write
    if (!config.read_only) {
      Spinner spinner("Large file: writing");
      spinner.start();

      std::string src = tmp_data + "/large.bin";
      std::string dst = bench_dir + "/large.bin";

      timer.start();

      std::ifstream in(src, std::ios::binary);
      std::ofstream out(dst, std::ios::binary);

      constexpr size_t buffer_size = 1024 * 1024;
      std::vector<char> buffer(buffer_size);

      while (in.read(buffer.data(), static_cast<std::streamsize>(buffer_size)) || in.gcount() > 0) {
        out.write(buffer.data(), in.gcount());
      }
      out.close();

#ifdef __linux__
      syncfs(fileno(fopen(dst.c_str(), "r")));
#else
      sync();
#endif

      results.large_write_ms = timer.elapsed_ms();
      uint64_t large_bytes = static_cast<uint64_t>(config.large_file_size_mb) * 1024 * 1024;
      results.large_write_mbps = (large_bytes / 1048576.0) * 1000.0 / results.large_write_ms;

      spinner.stop_with_result(fmt::format("{:.1f} MB/s", results.large_write_mbps));
    }

    // Step 5: Large file read
    if (!config.write_only) {
      Spinner spinner("Large file: reading");
      spinner.start();

      std::string path = bench_dir + "/large.bin";

      // Drop kernel page cache for cold read test
      drop_caches();

      timer.start();

      std::ifstream file(path, std::ios::binary);

      // Use 8MB buffer to match FUSE max_read for fewer RPC round trips
      constexpr size_t buffer_size = 8 * 1024 * 1024;
      std::vector<char> buffer(buffer_size);

      while (file.read(buffer.data(), static_cast<std::streamsize>(buffer_size))
             || file.gcount() > 0) {
        // Read data
      }

      results.large_read_ms = timer.elapsed_ms();
      uint64_t large_bytes = static_cast<uint64_t>(config.large_file_size_mb) * 1024 * 1024;
      results.large_read_mbps = (large_bytes / 1048576.0) * 1000.0 / results.large_read_ms;

      spinner.stop_with_result(fmt::format("{:.1f} MB/s", results.large_read_mbps));
    }

    // Step 6: Verify integrity (skip in write_only mode since we didn't read)
    if (config.verify && !config.write_only) {
      Spinner spinner("Verifying data integrity");
      spinner.start();

      std::string src = tmp_data + "/large.bin";
      std::string dst = bench_dir + "/large.bin";

      std::string src_hash = sha256_file(src);
      std::string dst_hash = sha256_file(dst);

      results.integrity_passed = (src_hash == dst_hash && !src_hash.empty());

      if (results.integrity_passed) {
        spinner.stop_with_result("SHA-256 match");
      } else {
        spinner.stop(false);
      }
    } else {
      results.integrity_passed = true;
    }

    print_results_table(config, results);
    cleanup();

    return results.integrity_passed ? 0 : 1;
  }

}  // namespace ghostfs
