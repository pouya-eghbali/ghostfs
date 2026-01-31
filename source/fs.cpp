#define FUSE_USE_VERSION 29

#include <assert.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
#include <ghostfs/crypto.h>
#include <ghostfs/fs.h>
#include <ghostfs/thread_pool.h>
#include <ghostfs/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <list>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

// Cap'n'Proto
#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/serialize-packed.h>
#include <kj/async-io.h>
#include <kj/async.h>
#include <kj/compat/tls.h>
#include <kj/threadlocal.h>

#include <condition_variable>
#include <mutex>

// Timeout constants (milliseconds)
constexpr uint64_t CONNECTION_TIMEOUT_MS = 5000;  // 5 seconds for connection
constexpr uint64_t RPC_TIMEOUT_MS = 30000;        // 30 seconds for RPC calls

// CAPNPROTO

#include <access.capnp.h>
#include <access.response.capnp.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <create.capnp.h>
#include <create.response.capnp.h>
#include <getattr.capnp.h>
#include <getattr.response.capnp.h>
#include <ghostfs.capnp.h>
#include <lookup.capnp.h>
#include <lookup.response.capnp.h>
#include <mkdir.capnp.h>
#include <mkdir.response.capnp.h>
#include <mknod.capnp.h>
#include <mknod.response.capnp.h>
#include <open.capnp.h>
#include <open.response.capnp.h>
#include <read.capnp.h>
#include <read.response.capnp.h>
#include <readdir.capnp.h>
#include <readdir.response.capnp.h>
#include <readlink.capnp.h>
#include <readlink.response.capnp.h>
#include <release.capnp.h>
#include <release.response.capnp.h>
#include <rename.capnp.h>
#include <rename.response.capnp.h>
#include <rmdir.capnp.h>
#include <rmdir.response.capnp.h>
#include <setattr.capnp.h>
#include <setattr.response.capnp.h>
#include <setxattr.capnp.h>
#include <setxattr.response.capnp.h>
#include <symlink.capnp.h>
#include <symlink.response.capnp.h>
#include <sys/xattr.h>
#include <unlink.capnp.h>
#include <unlink.response.capnp.h>
#include <write.capnp.h>
#include <write.response.capnp.h>
#include <openandread.capnp.h>
#include <openandread.response.capnp.h>

uint8_t max_write_back_cache = 64;  // Batch 64 writes before flushing (was 8)
uint8_t max_read_ahead_cache = 8;

// Stub functions for API compatibility (instrumentation removed for performance)
void print_read_stats() {}
void reset_read_stats() {}

// ============== FILE SIZE TRACKING ==============
// Track file sizes from open() to enable small file fast path
static constexpr size_t SMALL_FILE_THRESHOLD = 1 * 1024 * 1024;  // 1MB
static std::shared_mutex g_file_size_mutex;
static std::unordered_map<uint64_t, size_t> g_file_sizes;  // fh -> size
// ============== END FILE SIZE TRACKING ==============

// ============== SMALL FILE FAST PATH CACHE ==============
// Minimal-overhead cache for complete small files from openAndRead.
// Bypasses the complex prefetch system for files that fit in one RPC response.
// Benefits: 1 shared_lock + 1 hash lookup vs 3 mutex locks + 3 hash lookups
struct SmallFilePrefetch {
  std::vector<char> data;
};
static std::shared_mutex g_small_file_mutex;  // Allow concurrent reads
static std::unordered_map<uint64_t, SmallFilePrefetch> g_small_file_cache;  // fh -> data
// ============== END SMALL FILE FAST PATH CACHE ==============

struct cached_write {
  fuse_req_t req;
  fuse_ino_t ino;
  std::unique_ptr<char[]> buf;
  size_t size;
  off_t off;
  struct fuse_file_info fi;  // Store copy, not pointer (stack memory invalid after write returns)
};

// ============== SIMPLE ASYNC WRITE BUFFER SYSTEM ==============
// Double-buffered async writes - no coalescing, just parallel send
// 1. Writes go into current buffer, reply immediately
// 2. When buffer is full, swap to second buffer
// 3. Background thread flushes full buffer using bulkWriteRequest

static constexpr size_t ASYNC_WRITE_BUFFER_COUNT = 64;  // Writes per buffer before swap

// Forward declaration
void do_simple_flush(std::vector<cached_write>& writes);

class SimpleWriteManager {
public:
  std::vector<cached_write> buffers[2];
  std::atomic<int> current_buffer{0};
  std::atomic<bool> flush_in_progress{false};
  std::mutex swap_mutex;
  std::condition_variable flush_cv;
  std::thread flush_thread;
  std::atomic<bool> shutdown{false};

  SimpleWriteManager() {
    buffers[0].reserve(ASYNC_WRITE_BUFFER_COUNT);
    buffers[1].reserve(ASYNC_WRITE_BUFFER_COUNT);
    flush_thread = std::thread([this]() { flush_loop(); });
  }

  ~SimpleWriteManager() {
    shutdown.store(true);
    flush_cv.notify_all();
    if (flush_thread.joinable()) {
      flush_thread.join();
    }
    // Flush any remaining data
    flush_sync();
  }

  // Add write and reply immediately
  void add_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size,
                 off_t off, struct fuse_file_info* fi) {
    // Create cached_write entry
    cached_write cache;
    cache.req = req;
    cache.ino = ino;
    cache.buf = std::make_unique<char[]>(size);
    cache.size = size;
    cache.off = off;
    cache.fi = *fi;
    std::memcpy(cache.buf.get(), buf, size);

    {
      std::unique_lock<std::mutex> lock(swap_mutex);
      auto& current = buffers[current_buffer.load()];
      current.push_back(std::move(cache));

      // Buffer full? Swap and trigger flush
      if (current.size() >= ASYNC_WRITE_BUFFER_COUNT) {
        trigger_flush(lock);
      }
    }

    // Reply immediately - async benefit comes from background send
    fuse_reply_write(req, size);
  }

  // Synchronous flush (for close/fsync)
  void flush_sync() {
    std::unique_lock<std::mutex> lock(swap_mutex);

    // Wait for in-progress flush
    flush_cv.wait(lock, [this]() {
      return !flush_in_progress.load() || shutdown.load();
    });

    auto& current = buffers[current_buffer.load()];
    if (!current.empty()) {
      do_simple_flush(current);
      current.clear();
    }
  }

  // Flush specific file handle
  void flush_fh(uint64_t /*fh*/) {
    flush_sync();  // Simple: flush everything
  }

private:
  void trigger_flush(std::unique_lock<std::mutex>& lock) {
    // Wait if previous flush still in progress
    flush_cv.wait(lock, [this]() {
      return !flush_in_progress.load() || shutdown.load();
    });

    if (shutdown.load()) return;

    // Swap buffers
    int old_buffer = current_buffer.load();
    int new_buffer = 1 - old_buffer;

    // Clear new buffer
    buffers[new_buffer].clear();

    current_buffer.store(new_buffer);
    flush_in_progress.store(true);

    // Wake flush thread
    flush_cv.notify_all();
  }

  void flush_loop() {
    while (!shutdown.load()) {
      std::unique_lock<std::mutex> lock(swap_mutex);
      flush_cv.wait(lock, [this]() {
        return flush_in_progress.load() || shutdown.load();
      });

      if (shutdown.load()) break;

      // Flush old buffer
      int old_buffer = 1 - current_buffer.load();
      auto& to_flush = buffers[old_buffer];

      lock.unlock();  // Release lock during RPC

      if (!to_flush.empty()) {
        do_simple_flush(to_flush);
        to_flush.clear();
      }

      flush_in_progress.store(false);
      flush_cv.notify_all();
    }
  }
};

// Global write manager
static SimpleWriteManager& get_write_manager() {
  static SimpleWriteManager manager;
  return manager;
}
// ============== END ASYNC WRITE BUFFER SYSTEM ==============

// ============== PROACTIVE PREFETCH SYSTEM (JuiceFS-style) ==============
// This implements a proactive prefetch system where:
// 1. Persistent worker threads fetch blocks ahead of reads
// 2. Session tracking detects sequential patterns and queues prefetches
// 3. Reads hit cache most of the time; workers keep cache warm

// Configuration
static constexpr size_t PREFETCH_BLOCK_SIZE = 4 * 1024 * 1024;  // 4MB blocks (matches JuiceFS)
static constexpr size_t PREFETCH_QUEUE_SIZE = 75;   // Queue matches worker count
static constexpr size_t PREFETCH_WORKERS = 75;      // Match JuiceFS (75 goroutines)
static constexpr size_t PREFETCH_WINDOW = 20;       // Prefetch 20 blocks ahead (80MB)
static constexpr size_t MAX_CACHED_BLOCKS = 75;     // 300MB max cache per file (matches JuiceFS default)
// Only enable prefetch after reading this many bytes sequentially
// This prevents read amplification for small files
static constexpr size_t SEQ_THRESHOLD = 256 * 1024; // 256KB of sequential reads before prefetching

// Block states
static constexpr int BLOCK_EMPTY = 0;
static constexpr int BLOCK_FETCHING = 1;
static constexpr int BLOCK_READY = 2;
static constexpr int BLOCK_ERROR = -1;

// A prefetch request in the queue
struct PrefetchRequest {
  fuse_ino_t ino;
  uint64_t fh;           // File handle
  off_t offset;          // Block-aligned offset
  uint64_t flags;        // Open flags for RPC
};

// Cached block with data
struct CachedBlock {
  std::vector<char> data;
  off_t offset{0};
  size_t valid_size{0};
  std::atomic<int> state{BLOCK_EMPTY};
  std::mutex mtx;
  std::condition_variable cv;

  CachedBlock() { data.resize(PREFETCH_BLOCK_SIZE); }

  bool contains(off_t off, size_t size) const {
    if (state.load(std::memory_order_acquire) != BLOCK_READY) return false;
    if (valid_size == 0) return false;
    return off >= offset && (off + static_cast<off_t>(size)) <= (offset + static_cast<off_t>(valid_size));
  }

  const char* get_data(off_t off) const {
    return data.data() + (off - offset);
  }

  size_t available_from(off_t off) const {
    if (off < offset) return 0;
    off_t end = offset + static_cast<off_t>(valid_size);
    if (off >= end) return 0;
    return static_cast<size_t>(end - off);
  }
};

// Per-file prefetch session tracking sequential reads
struct PrefetchSession {
  std::atomic<off_t> last_offset{0};
  std::atomic<off_t> prefetch_offset{0};   // Next offset to prefetch
  std::atomic<size_t> seq_length{0};       // Sequential read length so far
  fuse_ino_t ino{0};
  uint64_t fh{0};
  uint64_t flags{0};

  // Block cache: map from aligned offset to block
  // Using shared_ptr to avoid use-after-free when blocks are evicted while in use
  std::unordered_map<off_t, std::shared_ptr<CachedBlock>> blocks;
  std::mutex blocks_mutex;
  std::list<off_t> lru_order;  // For eviction

  // Check if offset is sequential with previous reads
  bool is_sequential(off_t off) {
    off_t last = last_offset.load(std::memory_order_relaxed);
    // Sequential if reading at or near end of last read
    return (off >= last && off <= last + 2 * static_cast<off_t>(PREFETCH_BLOCK_SIZE));
  }

  // Update tracking after a read
  void record_read(off_t off, size_t size) {
    if (is_sequential(off)) {
      seq_length.fetch_add(size, std::memory_order_relaxed);
    } else {
      seq_length.store(size, std::memory_order_relaxed);
    }
    last_offset.store(off + static_cast<off_t>(size), std::memory_order_relaxed);
  }

  // Get or create a cached block (returns shared_ptr to keep block alive)
  std::shared_ptr<CachedBlock> get_block(off_t aligned_off) {
    std::lock_guard<std::mutex> lock(blocks_mutex);
    auto& block = blocks[aligned_off];
    if (!block) {
      block = std::make_shared<CachedBlock>();
      block->offset = aligned_off;
    }
    // Move to front of LRU
    lru_order.remove(aligned_off);
    lru_order.push_front(aligned_off);
    // Evict if over limit
    while (blocks.size() > MAX_CACHED_BLOCKS && lru_order.size() > 0) {
      off_t evict = lru_order.back();
      lru_order.pop_back();
      blocks.erase(evict);
    }
    return block;  // Return shared_ptr, not raw pointer
  }

  // Find a block that contains data (returns shared_ptr to keep block alive)
  std::shared_ptr<CachedBlock> find_block(off_t off, size_t size) {
    off_t aligned = (off / static_cast<off_t>(PREFETCH_BLOCK_SIZE)) * static_cast<off_t>(PREFETCH_BLOCK_SIZE);
    std::lock_guard<std::mutex> lock(blocks_mutex);
    auto it = blocks.find(aligned);
    if (it != blocks.end() && it->second->contains(off, size)) {
      // Move to front of LRU
      lru_order.remove(aligned);
      lru_order.push_front(aligned);
      return it->second;  // Return shared_ptr, not raw pointer
    }
    return nullptr;
  }

  // Check if block is being fetched
  bool is_fetching(off_t aligned_off) {
    std::lock_guard<std::mutex> lock(blocks_mutex);
    auto it = blocks.find(aligned_off);
    if (it != blocks.end()) {
      return it->second->state.load(std::memory_order_acquire) == BLOCK_FETCHING;
    }
    return false;
  }
};

// Global prefetch queue and workers
class PrefetchManager {
public:
  std::queue<PrefetchRequest> queue;
  std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::atomic<bool> shutdown{false};
  std::vector<std::thread> workers;

  // Sessions per file handle (shared_ptr so workers can hold references safely)
  std::unordered_map<uint64_t, std::shared_ptr<PrefetchSession>> sessions;
  std::mutex sessions_mutex;

  PrefetchManager() {
    // Start worker threads
    for (size_t i = 0; i < PREFETCH_WORKERS; ++i) {
      workers.emplace_back([this, i]() { worker_loop(i); });
    }
  }

  ~PrefetchManager() {
    shutdown.store(true);
    queue_cv.notify_all();
    for (auto& w : workers) {
      if (w.joinable()) w.join();
    }
  }

  std::shared_ptr<PrefetchSession> get_session(uint64_t fh) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    auto& sess = sessions[fh];
    if (!sess) {
      sess = std::make_shared<PrefetchSession>();
      sess->fh = fh;
    }
    return sess;  // Return shared_ptr - caller keeps session alive
  }

  void remove_session(uint64_t fh) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    sessions.erase(fh);
  }

  // Queue a prefetch request (non-blocking, drops if queue full)
  void enqueue(const PrefetchRequest& req) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    if (queue.size() < PREFETCH_QUEUE_SIZE) {
      queue.push(req);
      queue_cv.notify_one();
    }
    // Drop if full (backpressure like JuiceFS)
  }

  // Queue multiple prefetch requests for upcoming blocks
  void prefetch_ahead(fuse_ino_t ino, uint64_t fh, uint64_t flags, off_t current_off) {
    auto sess = get_session(fh);
    sess->ino = ino;
    sess->flags = flags;

    off_t aligned = (current_off / static_cast<off_t>(PREFETCH_BLOCK_SIZE)) * static_cast<off_t>(PREFETCH_BLOCK_SIZE);

    // Prefetch next PREFETCH_WINDOW blocks
    for (size_t i = 1; i <= PREFETCH_WINDOW; ++i) {
      off_t prefetch_off = aligned + static_cast<off_t>(i * PREFETCH_BLOCK_SIZE);

      // Skip if already cached or being fetched
      auto block = sess->get_block(prefetch_off);
      int state = block->state.load(std::memory_order_acquire);
      if (state == BLOCK_READY || state == BLOCK_FETCHING) {
        continue;
      }

      // Try to claim for fetching
      int expected = BLOCK_EMPTY;
      if (block->state.compare_exchange_strong(expected, BLOCK_FETCHING)) {
        PrefetchRequest req{ino, fh, prefetch_off, flags};
        enqueue(req);
      }
    }
  }

private:
  void worker_loop(size_t worker_id);  // Forward declaration, defined after do_read_rpc
};

// Global prefetch manager (lazy-initialized)
static PrefetchManager& get_prefetch_manager() {
  static PrefetchManager manager;
  return manager;
}

// Helper functions for prefetch buffer management
void remove_prefetch_buffer(uint64_t fh) {
  get_prefetch_manager().remove_session(fh);
}

// Store prefetched data from openAndRead directly into the proactive cache
// This allows reads to follow the standard proactive_read path
static constexpr size_t OPEN_PREFETCH_SIZE = 64 * 1024;  // Prefetch first 64KB on open

void store_open_prefetch(uint64_t fh, fuse_ino_t ino, const char* buf, size_t size) {
  if (size == 0) return;

  auto& manager = get_prefetch_manager();
  auto sess = manager.get_session(fh);
  sess->ino = ino;
  sess->fh = fh;

  // Store in block at offset 0
  auto block = sess->get_block(0);
  std::lock_guard<std::mutex> lock(block->mtx);

  // Copy data into the block
  std::memcpy(block->data.data(), buf, size);
  block->offset = 0;
  block->valid_size = size;
  block->state.store(BLOCK_READY, std::memory_order_release);

  // Update session tracking so sequential detection works
  sess->last_offset.store(static_cast<off_t>(size), std::memory_order_relaxed);
  sess->seq_length.store(size, std::memory_order_relaxed);
}
// ============== END PROACTIVE PREFETCH SYSTEM ==============

// Encryption state
static bool g_encryption_enabled = false;
static uint8_t g_encryption_key[ghostfs::crypto::KEY_SIZE];
static std::unordered_map<uint64_t, ghostfs::crypto::FileContext>
    g_crypto_contexts;  // keyed by file handle
static std::mutex g_crypto_mutex;

// Global thread pool for crypto operations (lazy-initialized)
static ghostfs::ThreadPool &get_crypto_pool() {
  static ghostfs::ThreadPool pool(std::thread::hardware_concurrency());
  return pool;
}

// Thread-safe inode mapping with bounded growth
constexpr size_t MAX_INODE_CACHE_SIZE = 100000;
constexpr size_t INODE_EVICT_BATCH = 10000;  // Evict 10% at a time
std::unordered_map<uint64_t, std::string> ino_to_path;
std::unordered_map<std::string, uint64_t> path_to_ino;
std::atomic<uint64_t> current_ino{1};
std::shared_mutex g_inode_mutex;
static uint64_t min_valid_ino = 2;  // Track eviction boundary (skip root inode 1)

// Thread-safe helper functions for inode management
std::string get_path_for_ino(uint64_t ino) {
  std::shared_lock lock(g_inode_mutex);
  auto it = ino_to_path.find(ino);
  return (it != ino_to_path.end()) ? it->second : "";
}

uint64_t get_ino_for_path(const std::string &path) {
  std::shared_lock lock(g_inode_mutex);
  auto it = path_to_ino.find(path);
  return (it != path_to_ino.end()) ? it->second : 0;
}

uint64_t assign_inode(const std::string &path) {
  std::unique_lock lock(g_inode_mutex);
  auto it = path_to_ino.find(path);
  if (it != path_to_ino.end()) return it->second;

  // Evict old entries if at capacity (batch eviction for efficiency)
  if (ino_to_path.size() >= MAX_INODE_CACHE_SIZE) {
    uint64_t evict_threshold = min_valid_ino + INODE_EVICT_BATCH;
    for (auto iter = ino_to_path.begin(); iter != ino_to_path.end();) {
      if (iter->first > 1 && iter->first < evict_threshold) {  // Don't evict root inode
        path_to_ino.erase(iter->second);
        iter = ino_to_path.erase(iter);
      } else {
        ++iter;
      }
    }
    min_valid_ino = evict_threshold;
  }

  uint64_t ino = ++current_ino;
  ino_to_path[ino] = path;
  path_to_ino[path] = ino;
  return ino;
}

// ============== ATTRIBUTE CACHE ==============
// Cache attributes from readdir to avoid getattr RPCs
struct CachedAttr {
  uint32_t mode;
  uint64_t size;
  uint64_t mtime;      // seconds
  uint32_t mtime_nsec; // nanoseconds
  std::chrono::steady_clock::time_point cached_at;
};

static std::shared_mutex g_attr_cache_mutex;
static std::unordered_map<uint64_t, CachedAttr> g_attr_cache;  // ino -> attrs
static std::atomic<bool> g_attr_cache_has_data{false};  // Fast check to avoid lock when empty
static constexpr auto ATTR_CACHE_TTL = std::chrono::seconds(60);  // Match FUSE timeout

// Store attributes in cache (called from readdir)
void cache_attrs(uint64_t ino, uint32_t mode, uint64_t size, uint64_t mtime, uint32_t mtime_nsec) {
  std::unique_lock lock(g_attr_cache_mutex);
  g_attr_cache[ino] = CachedAttr{mode, size, mtime, mtime_nsec, std::chrono::steady_clock::now()};
  g_attr_cache_has_data.store(true, std::memory_order_release);
}

// Try to get cached attributes (called from getattr)
bool get_cached_attrs(uint64_t ino, CachedAttr& out) {
  // Fast path: skip lock if cache is empty
  if (!g_attr_cache_has_data.load(std::memory_order_acquire)) return false;

  std::shared_lock lock(g_attr_cache_mutex);
  auto it = g_attr_cache.find(ino);
  if (it == g_attr_cache.end()) return false;

  // Check TTL
  auto age = std::chrono::steady_clock::now() - it->second.cached_at;
  if (age > ATTR_CACHE_TTL) return false;

  out = it->second;
  return true;
}
// ============== END ATTRIBUTE CACHE ==============

bool has_inode(uint64_t ino) {
  std::shared_lock lock(g_inode_mutex);
  return ino_to_path.contains(ino);
}

bool has_path(const std::string &path) {
  std::shared_lock lock(g_inode_mutex);
  return path_to_ino.contains(path);
}

void remove_inode(uint64_t ino) {
  std::unique_lock lock(g_inode_mutex);
  auto it = ino_to_path.find(ino);
  if (it != ino_to_path.end()) {
    path_to_ino.erase(it->second);
    ino_to_path.erase(it);
  }
}

void update_inode_path(uint64_t ino, const std::string &old_path, const std::string &new_path) {
  std::unique_lock lock(g_inode_mutex);
  ino_to_path[ino] = new_path;
  path_to_ino[new_path] = ino;
  path_to_ino.erase(old_path);
}

// Global connection parameters for thread-local client creation
struct ConnectionParams {
  std::string host;
  int port;
  std::string user;
  std::string token;
  std::string cert;
  bool use_tls = false;
};
ConnectionParams g_conn_params;

// Thread-local Cap'n Proto state
struct ThreadLocalRpc {
  std::unique_ptr<kj::AsyncIoContext> ioContext;
  std::unique_ptr<capnp::TwoPartyClient> twoParty;
  kj::Own<kj::AsyncIoStream> connection;
  std::optional<GhostFS::Client> client;
  bool initialized = false;

  kj::Timer &getTimer() { return ioContext->provider->getTimer(); }

  void init() {
    if (initialized) return;

    ioContext = std::make_unique<kj::AsyncIoContext>(kj::setupAsyncIo());
    auto &timer = ioContext->provider->getTimer();

    if (g_conn_params.cert.length() || g_conn_params.use_tls) {
      kj::TlsContext::Options options;
      std::optional<kj::TlsCertificate> caCert;
      if (g_conn_params.cert.length()) {
        // Use explicit CA certificate
        caCert.emplace(g_conn_params.cert);
        options.trustedCertificates = kj::arrayPtr(&*caCert, 1);
      }
      // When no cert is provided (--tls without --cert), use system trust store (default)

      kj::TlsContext tls(kj::mv(options));
      auto network = tls.wrapNetwork(ioContext->provider->getNetwork());

      // DNS resolution with timeout
      auto addressPromise = network->parseAddress(g_conn_params.host, g_conn_params.port);
      auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                                .then([]() -> kj::Own<kj::NetworkAddress> {
                                  KJ_FAIL_REQUIRE("DNS resolution timed out");
                                });
      auto address
          = addressPromise.exclusiveJoin(kj::mv(addressTimeout)).wait(ioContext->waitScope);

      // TCP connection with timeout
      auto connectPromise = address->connect();
      auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                                .then([]() -> kj::Own<kj::AsyncIoStream> {
                                  KJ_FAIL_REQUIRE("Connection timed out");
                                });
      connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout)).wait(ioContext->waitScope);
    } else {
      // DNS resolution with timeout
      auto addressPromise
          = ioContext->provider->getNetwork().parseAddress(g_conn_params.host, g_conn_params.port);
      auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                                .then([]() -> kj::Own<kj::NetworkAddress> {
                                  KJ_FAIL_REQUIRE("DNS resolution timed out");
                                });
      auto address
          = addressPromise.exclusiveJoin(kj::mv(addressTimeout)).wait(ioContext->waitScope);

      // TCP connection with timeout
      auto connectPromise = address->connect();
      auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                                .then([]() -> kj::Own<kj::AsyncIoStream> {
                                  KJ_FAIL_REQUIRE("Connection timed out");
                                });
      connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout)).wait(ioContext->waitScope);
    }

    twoParty = std::make_unique<capnp::TwoPartyClient>(*connection);
    auto rpcCapability = twoParty->bootstrap();
    auto authClient = rpcCapability.castAs<GhostFSAuth>();
    auto request = authClient.authRequest();
    request.setUser(g_conn_params.user);
    request.setToken(g_conn_params.token);

    // Auth RPC with timeout
    auto authPromise = request.send();
    auto authTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                           .then([]() -> capnp::Response<GhostFSAuth::AuthResults> {
                             KJ_FAIL_REQUIRE("Authentication timed out");
                           });
    auto result = authPromise.exclusiveJoin(kj::mv(authTimeout)).wait(ioContext->waitScope);

    if (!result.getAuthSuccess()) {
      throw std::runtime_error("Thread-local authentication failed");
    }

    client = result.getGhostFs();
    initialized = true;
  }
};

thread_local ThreadLocalRpc tl_rpc;

// Helper to get thread-local RPC client
inline ThreadLocalRpc &getRpc() {
  tl_rpc.init();
  return tl_rpc;
}

// Helper for RPC calls with timeout - uses template deduction to avoid explicit type annotations
template <typename Promise>
auto waitWithTimeout(Promise &&promise, kj::Timer &timer, kj::WaitScope &waitScope)
    -> decltype(kj::fwd<Promise>(promise).wait(waitScope)) {
  using ResultType = decltype(kj::fwd<Promise>(promise).wait(waitScope));
  auto timeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS).then([]() -> ResultType {
    KJ_FAIL_REQUIRE("RPC timeout");
  });
  return kj::fwd<Promise>(promise).exclusiveJoin(kj::mv(timeout)).wait(waitScope);
}

#define LOCAL_MIN(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off,
                             size_t maxsize) {
  if (off < (int64_t)bufsize) {
    return fuse_reply_buf(req, buf + off, LOCAL_MIN(bufsize - off, maxsize));

  } else {
    return fuse_reply_buf(req, NULL, 0);
  }
}

// Old global Cap'n Proto state removed - now using thread-local storage (tl_rpc)

uint64_t get_parent_ino(uint64_t ino, std::string path) {
  if (ino == 1) {
    return ino;
  }

  std::filesystem::path parent_path = std::filesystem::path(path).parent_path();
  uint64_t parent_ino = get_ino_for_path(parent_path.string());

  return parent_ino;
}

// Translate open flags from macOS to Linux values for cross-platform RPC
static int64_t translate_flags_to_linux(int64_t flags) {
#ifdef __APPLE__
  // Access mode bits (O_RDONLY=0, O_WRONLY=1, O_RDWR=2) are the same on both platforms
  int64_t result = flags & O_ACCMODE;

  // macOS flag value → Linux flag value
  if (flags & 0x0004) result |= 0x0800;      // O_NONBLOCK
  if (flags & 0x0008) result |= 0x0400;      // O_APPEND
  if (flags & 0x0080) result |= 0x101000;    // O_SYNC
  if (flags & 0x0100) result |= 0x20000;     // O_NOFOLLOW
  if (flags & 0x0200) result |= 0x0040;      // O_CREAT
  if (flags & 0x0400) result |= 0x0200;      // O_TRUNC
  if (flags & 0x0800) result |= 0x0080;      // O_EXCL
  if (flags & 0x100000) result |= 0x10000;   // O_DIRECTORY
  if (flags & 0x1000000) result |= 0x80000;  // O_CLOEXEC

  return result;
#else
  return flags;
#endif
}

template <class T> void fillFileInfo(T *fuseFileInfo, struct fuse_file_info *fi) {
  if (!fi) return;

  fuseFileInfo->setFlags(translate_flags_to_linux(fi->flags));
  fuseFileInfo->setWritepage(fi->writepage);
  fuseFileInfo->setDirectIo(fi->direct_io);
  fuseFileInfo->setKeepCache(fi->keep_cache);
  fuseFileInfo->setFlush(fi->flush);
  fuseFileInfo->setNonseekable(fi->nonseekable);
  /* fuseFileInfo->setCacheReaddir(fi->cache_readdir); */
  fuseFileInfo->setPadding(fi->padding);
  fuseFileInfo->setFh(fi->fh);
  fuseFileInfo->setLockOwner(fi->lock_owner);
  /* fuseFileInfo->setPollEvents(fi->poll_events); */
  /* fuseFileInfo->setNoflush(fi->noflush); */
}

/**
 * Notes: fuse_ino_t is uint64_t
 *        off_t is apparently long int
 *        size_t is apparently unsigned int
 *        fuse_file_info check https://libfuse.github.io/doxygen/structfuse__file__info.html
 *        struct stat check https://pubs.opengroup.org/onlinepubs/7908799/xsh/sysstat.h.html and
 *                          https://doc.rust-lang.org/std/os/linux/raw/struct.stat.html
 *
 * Cool little trick:
 *        gcc -E -xc -include time.h /dev/null | grep time_t
 *        gcc -E -xc -include sys/types.h /dev/null | grep nlink_t
 *
 * Useful stuff:
 *        http://www.sde.cs.titech.ac.jp/~gondow/dwarf2-xml/HTML-rxref/app/gcc-3.3.2/lib/gcc-lib/sparc-sun-solaris2.8/3.3.2/include/sys/types.h.html
 *        Apparently Solaris devs knew how to write non-cryptic code
 */

int ghostfs_stat(fuse_ino_t ino, int64_t fh, struct stat *stbuf) {
  if (fh == 0 || ino == 1) {
    return ghostfs_stat(ino, stbuf);
  }

  int res = fstat(fh, stbuf);
  stbuf->st_ino = ino;
  return res;
}

int ghostfs_stat(fuse_ino_t ino, struct stat *stbuf) {
  if (ino == 1) {
    // This is the fs root
    stbuf->st_ino = ino;
    stbuf->st_mode = S_IFDIR | 0777;
    stbuf->st_nlink = 2;
    return 0;
  }

  std::string path = get_path_for_ino(ino);
  if (path.empty()) {
    // File is unknown
    return -1;
  }

  int res = lstat(path.c_str(), stbuf);
  stbuf->st_ino = ino;

  return res;
}

// DirbufBuilder: Pre-allocating directory buffer builder with O(1) amortized growth
class DirbufBuilder {
  std::vector<char> buffer;
  size_t used = 0;

public:
  explicit DirbufBuilder(size_t estimated_entries = 64) {
    // Estimate ~128 bytes per entry (name + stat + padding)
    buffer.reserve(estimated_entries * 128);
  }

  void add(fuse_req_t req, const char *name, fuse_ino_t ino) {
    struct stat stbuf = {};
    stbuf.st_ino = ino;

    size_t entry_size = fuse_add_direntry(req, nullptr, 0, name, nullptr, 0);

    // Grow by 2x if needed (amortized O(1))
    if (used + entry_size > buffer.size()) {
      buffer.resize(std::max(buffer.size() * 2, used + entry_size));
    }

    fuse_add_direntry(req, buffer.data() + used, buffer.size() - used, name, &stbuf,
                      used + entry_size);
    used += entry_size;
  }

  const char *data() const { return buffer.data(); }
  size_t size() const { return used; }
};

// Legacy dirbuf_add for backwards compatibility (if needed elsewhere)
void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino) {
  struct stat stbuf;
  size_t oldsize = b->size;
  b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
  b->p = (char *)realloc(b->p, b->size);
  memset(&stbuf, 0, sizeof(stbuf));
  stbuf.st_ino = ino;
  fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  // Try attribute cache first (populated by readdir)
  CachedAttr cached;
  if (!g_encryption_enabled && get_cached_attrs(ino, cached)) {
    struct stat attr;
    memset(&attr, 0, sizeof(attr));
    attr.st_ino = ino;
    attr.st_mode = cached.mode;
    attr.st_nlink = S_ISDIR(cached.mode) ? 2 : 1;  // Reasonable default
    attr.st_uid = geteuid();
    attr.st_gid = getegid();
    attr.st_size = cached.size;
    attr.st_atime = cached.mtime;  // Use mtime for atime/ctime
    attr.st_mtime = cached.mtime;
    attr.st_ctime = cached.mtime;
    attr.st_blksize = 4096;  // Reasonable default
    attr.st_blocks = (cached.size + 511) / 512;
    #ifdef __APPLE__
    attr.st_mtimespec.tv_sec = cached.mtime;
    attr.st_mtimespec.tv_nsec = cached.mtime_nsec;
    attr.st_atimespec = attr.st_mtimespec;
    attr.st_ctimespec = attr.st_mtimespec;
    #else
    attr.st_mtim.tv_sec = cached.mtime;
    attr.st_mtim.tv_nsec = cached.mtime_nsec;
    attr.st_atim = attr.st_mtim;
    attr.st_ctim = attr.st_mtim;
    #endif
    fuse_reply_attr(req, &attr, 60.0);
    return;
  }

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->getattrRequest();

    Getattr::Builder getattr = request.getReq();
    Getattr::FuseFileInfo::Builder fuseFileInfo = getattr.initFi();

    getattr.setIno(ino);

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    struct stat attr;

    memset(&attr, 0, sizeof(attr));

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    GetattrResponse::Attr::Reader attributes = response.getAttr();

    attr.st_dev = attributes.getStDev();
    attr.st_ino = attributes.getStIno();
    attr.st_mode = attributes.getStMode();
    attr.st_nlink = attributes.getStNlink();
    attr.st_uid = geteuid();  // attributes.getStUid();
    attr.st_gid = getegid();  // attributes.getStGid();
    attr.st_rdev = attributes.getStRdev();
    attr.st_size = attributes.getStSize();
    attr.st_atime = attributes.getStAtime();
    attr.st_mtime = attributes.getStMtime();
    attr.st_ctime = attributes.getStCtime();
    attr.st_blksize = attributes.getStBlksize();
    attr.st_blocks = attributes.getStBlocks();

    // Translate physical to logical size for encrypted regular files
    if (g_encryption_enabled && S_ISREG(attr.st_mode)) {
      attr.st_size = ghostfs::crypto::physical_to_logical_size(attr.st_size);
    }

    fuse_reply_attr(req, &attr, 60.0);
  } catch (const kj::Exception &e) {
    std::cerr << "getattr error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 */
static void ghostfs_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->lookupRequest();

    Lookup::Builder lookup = request.getReq();

    lookup.setParent(parent);
    lookup.setName(name);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    struct stat attr;

    memset(&attr, 0, sizeof(attr));

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));
    e.ino = response.getIno();
    e.attr_timeout = 60.0;
    e.entry_timeout = 60.0;

    LookupResponse::Attr::Reader attributes = response.getAttr();

    e.attr.st_dev = attributes.getStDev();
    e.attr.st_ino = attributes.getStIno();
    e.attr.st_mode = attributes.getStMode();
    e.attr.st_nlink = attributes.getStNlink();
    e.attr.st_uid = geteuid();  // attributes.getStUid();
    e.attr.st_gid = getegid();  // attributes.getStGid();
    e.attr.st_rdev = attributes.getStRdev();
    e.attr.st_size = attributes.getStSize();
    e.attr.st_atime = attributes.getStAtime();
    e.attr.st_mtime = attributes.getStMtime();
    e.attr.st_ctime = attributes.getStCtime();
    e.attr.st_blksize = attributes.getStBlksize();
    e.attr.st_blocks = attributes.getStBlocks();

    // Translate physical to logical size for encrypted regular files
    if (g_encryption_enabled && S_ISREG(e.attr.st_mode)) {
      e.attr.st_size = ghostfs::crypto::physical_to_logical_size(e.attr.st_size);
    }

    fuse_reply_entry(req, &e);
  } catch (const kj::Exception &ex) {
    std::cerr << "lookup error: " << ex.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief Readdir fuse low-level function (called when using ls)
 *
 * @param req
 * @param ino -> uint64_t
 * @param size -> unsigned int
 * @param off -> long int
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                               struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->readdirRequest();

    Readdir::Builder readdir = request.getReq();
    Readdir::FuseFileInfo::Builder fuseFileInfo = readdir.initFi();

    readdir.setIno(ino);
    readdir.setSize(size);
    readdir.setOff(off);

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    // Use DirbufBuilder with pre-allocation based on response size
    DirbufBuilder b(response.getEntries().size());

    for (ReaddirResponse::Entry::Reader entry : response.getEntries()) {
      b.add(req, entry.getName().cStr(), entry.getIno());
      // Cache attributes from readdir to avoid separate getattr RPCs
      if (entry.getMode() != 0) {  // Only cache if server provided attrs
        cache_attrs(entry.getIno(), entry.getMode(), entry.getSize(),
                    entry.getMtime(), entry.getMtimeNsec());
      }
    }

    reply_buf_limited(req, b.data(), b.size(), off, size);
  } catch (const kj::Exception &e) {
    std::cerr << "readdir error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();

    // For read-only, non-encrypted opens: use combined openAndRead RPC
    // This reduces 2 round-trips to 1 for small file reads
    // Data is stored directly in proactive cache so reads follow standard path
    bool is_read_only = (fi->flags & O_ACCMODE) == O_RDONLY;
    if (is_read_only && !g_encryption_enabled) {
      auto request = rpc.client->openAndReadRequest();

      OpenAndRead::Builder openAndRead = request.getReq();
      OpenAndRead::FuseFileInfo::Builder fuseFileInfo = openAndRead.initFi();

      openAndRead.setIno(ino);
      openAndRead.setSize(OPEN_PREFETCH_SIZE);
      openAndRead.setOff(0);
      fillFileInfo(&fuseFileInfo, fi);

      auto result = waitWithTimeout(request.send(), timer, waitScope);
      auto response = result.getRes();

      int64_t res = response.getRes();
      if (res == -1) {
        int err = response.getErrno();
        fuse_reply_err(req, err);
        return;
      }

      fi->fh = response.getFh();

      // Store prefetched data - use fast path cache for complete small files
      if (res > 0) {
        capnp::Data::Reader buf_reader = response.getBuf();
        const auto chars = buf_reader.asChars();

        if (static_cast<size_t>(res) < OPEN_PREFETCH_SIZE) {
          // Complete file fits in one response - use simple fast-path cache
          // This avoids the overhead of the proactive prefetch system
          SmallFilePrefetch prefetch;
          prefetch.data.assign(chars.begin(), chars.begin() + res);
          {
            std::unique_lock lock(g_small_file_mutex);
            g_small_file_cache[fi->fh] = std::move(prefetch);
          }
        } else {
          // File is larger than prefetch size - use proactive cache for reads
          store_open_prefetch(fi->fh, ino, chars.begin(), static_cast<size_t>(res));
        }
      }

      // Store file size for prefetch-ahead decision
      // If we got less data than requested, the file is exactly 'res' bytes
      // If we got OPEN_PREFETCH_SIZE bytes, the file could be larger - store 0 (unknown)
      size_t stored_size = (res >= 0 && static_cast<size_t>(res) < OPEN_PREFETCH_SIZE)
                           ? static_cast<size_t>(res) : 0;
      {
        std::unique_lock lock(g_file_size_mutex);
        g_file_sizes[fi->fh] = stored_size;
      }

      fuse_reply_open(req, fi);
      return;
    }

    // Standard open path for write modes or encrypted files
    auto request = rpc.client->openRequest();

    Open::Builder open = request.getReq();
    Open::FuseFileInfo::Builder fuseFileInfo = open.initFi();

    open.setIno(ino);

    // For encrypted files:
    // 1. Strip O_APPEND - Linux's pwrite() with O_APPEND ignores offset
    // 2. Ensure O_RDWR for RMW operations (partial block writes need to read existing data)
    struct fuse_file_info fi_for_server = *fi;
    if (g_encryption_enabled) {
      fi_for_server.flags &= ~O_APPEND;
      // If file was opened write-only, upgrade to read-write for RMW support
      if ((fi_for_server.flags & O_ACCMODE) == O_WRONLY) {
        fi_for_server.flags = (fi_for_server.flags & ~O_ACCMODE) | O_RDWR;
      }
    }
    fillFileInfo(&fuseFileInfo, &fi_for_server);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      int err = response.getErrno();
      fuse_reply_err(req, err);
      return;
    }

    OpenResponse::FuseFileInfo::Reader fi_response = response.getFi();

    fi->fh = fi_response.getFh();

    // Store file size for small file fast path in read
    size_t stored_size = response.getSize();
    {
      std::unique_lock lock(g_file_size_mutex);
      g_file_sizes[fi->fh] = stored_size;
    }

    // Initialize crypto context for encrypted files
    if (g_encryption_enabled) {
      ghostfs::crypto::FileContext ctx;
      ctx.is_encrypted = true;
      ctx.plaintext_size = -1;  // Unknown until first access
      std::memset(ctx.file_id, 0, ghostfs::crypto::FILE_ID_SIZE);

      // Try to read the header from existing file
      auto headerRequest = rpc.client->readRequest();
      Read::Builder headerRead = headerRequest.getReq();
      Read::FuseFileInfo::Builder headerFi = headerRead.initFi();

      headerRead.setIno(ino);
      headerRead.setSize(ghostfs::crypto::HEADER_SIZE);
      headerRead.setOff(0);
      fillFileInfo(&headerFi, fi);

      auto headerResult = waitWithTimeout(headerRequest.send(), timer, waitScope);
      auto headerResponse = headerResult.getRes();

      if (headerResponse.getRes() >= static_cast<int>(ghostfs::crypto::HEADER_SIZE)) {
        // File has a header, parse it
        capnp::Data::Reader headerBuf = headerResponse.getBuf();
        const uint8_t *headerData = headerBuf.asBytes().begin();
        uint16_t version;
        if (ghostfs::crypto::parse_header(headerData, ghostfs::crypto::HEADER_SIZE, ctx.file_id,
                                          &version)) {
          ctx.is_encrypted = true;
        }
      }
      // If no header or parsing failed, file_id stays zeroed and will be created on first write

      std::lock_guard<std::mutex> lock(g_crypto_mutex);
      g_crypto_contexts[fi->fh] = ctx;
    }

    fuse_reply_open(req, fi);
  } catch (const kj::Exception &e) {
    std::cerr << "open error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

// Encrypted read: reads and decrypts data from server
static void encrypted_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                           struct fuse_file_info *fi) {
  using namespace ghostfs::crypto;

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();

    // Calculate block range needed
    size_t start_block = get_block_number(off);
    size_t end_block = get_block_number(off + size - 1);
    size_t offset_in_first_block = get_offset_in_block(off);

    // Calculate physical read range
    int64_t phys_start = HEADER_SIZE + start_block * ENCRYPTED_BLOCK_SIZE;
    int64_t phys_size = (end_block - start_block + 1) * ENCRYPTED_BLOCK_SIZE;

    // Request encrypted blocks from server
    auto request = rpc.client->readRequest();
    Read::Builder read = request.getReq();
    Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

    read.setIno(ino);
    read.setSize(phys_size);
    read.setOff(phys_start);
    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    if (res == 0) {
      // EOF
      fuse_reply_buf(req, nullptr, 0);
      return;
    }

    capnp::Data::Reader buf_reader = response.getBuf();
    const uint8_t *encrypted_data = buf_reader.asBytes().begin();
    size_t encrypted_len = static_cast<size_t>(res);

    // Count complete blocks in the response
    size_t num_blocks = 0;
    size_t enc_offset = 0;
    while (enc_offset < encrypted_len) {
      size_t block_enc_size = (std::min)(ENCRYPTED_BLOCK_SIZE, encrypted_len - enc_offset);
      if (block_enc_size < NONCE_SIZE + TAG_SIZE) break;
      num_blocks++;
      enc_offset += block_enc_size;
    }

    // Allocate buffer for decrypted plaintext
    size_t max_plaintext = num_blocks * BLOCK_SIZE;
    std::vector<uint8_t> plaintext_buf(max_plaintext);
    std::vector<size_t> block_lengths(num_blocks);
    std::atomic<bool> decryption_failed{false};

    // Parallel decryption for multiple blocks using thread pool
    const size_t num_threads = std::min(num_blocks, (size_t)std::thread::hardware_concurrency());

    if (num_blocks >= 4 && num_threads > 1) {
      auto &pool = get_crypto_pool();
      std::vector<std::future<void>> futures;
      futures.reserve(num_threads);

      size_t blocks_per_thread = num_blocks / num_threads;
      size_t remaining_blocks = num_blocks % num_threads;

      size_t block_start = 0;
      for (size_t t = 0; t < num_threads; t++) {
        size_t thread_blocks = blocks_per_thread + (t < remaining_blocks ? 1 : 0);
        size_t thread_start = block_start;

        futures.push_back(pool.enqueue([&, thread_start, thread_blocks]() {
          for (size_t i = 0; i < thread_blocks && !decryption_failed; i++) {
            size_t block_idx = thread_start + i;
            size_t block_enc_offset = block_idx * ENCRYPTED_BLOCK_SIZE;
            size_t block_enc_size
                = (std::min)(ENCRYPTED_BLOCK_SIZE, encrypted_len - block_enc_offset);

            uint8_t *out_ptr = plaintext_buf.data() + (block_idx * BLOCK_SIZE);

            if (!decrypt_block(encrypted_data + block_enc_offset, block_enc_size, g_encryption_key,
                               out_ptr, &block_lengths[block_idx])) {
              decryption_failed = true;
            }
          }
        }));

        block_start += thread_blocks;
      }

      for (auto &f : futures) {
        f.get();
      }
    } else {
      // Sequential decryption for small reads
      enc_offset = 0;
      for (size_t i = 0; i < num_blocks; i++) {
        size_t block_enc_size = (std::min)(ENCRYPTED_BLOCK_SIZE, encrypted_len - enc_offset);
        uint8_t *out_ptr = plaintext_buf.data() + (i * BLOCK_SIZE);

        if (!decrypt_block(encrypted_data + enc_offset, block_enc_size, g_encryption_key, out_ptr,
                           &block_lengths[i])) {
          decryption_failed = true;
          break;
        }
        enc_offset += block_enc_size;
      }
    }

    if (decryption_failed) {
      std::cerr << "Decryption failed" << std::endl;
      fuse_reply_err(req, EIO);
      return;
    }

    // Compact plaintext blocks (they're at fixed offsets but may have variable lengths)
    // For most blocks this is a no-op since they're full BLOCK_SIZE
    size_t plaintext_total = 0;
    for (size_t i = 0; i < num_blocks; i++) {
      if (i > 0 && block_lengths[i] > 0) {
        // Move block data to compact position if there's a gap
        size_t expected_offset = plaintext_total;
        size_t actual_offset = i * BLOCK_SIZE;
        if (actual_offset != expected_offset) {
          std::memmove(plaintext_buf.data() + expected_offset, plaintext_buf.data() + actual_offset,
                       block_lengths[i]);
        }
      }
      plaintext_total += block_lengths[i];
    }

    // Extract requested range from plaintext
    if (plaintext_total <= offset_in_first_block) {
      fuse_reply_buf(req, nullptr, 0);
      return;
    }

    size_t available = plaintext_total - offset_in_first_block;
    size_t reply_size = (std::min)(size, available);

    fuse_reply_buf(req,
                   reinterpret_cast<const char *>(plaintext_buf.data() + offset_in_first_block),
                   reply_size);

  } catch (const kj::Exception &e) {
    std::cerr << "encrypted_read error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

// Encrypted write: encrypts and writes data to server
static void encrypted_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                            struct fuse_file_info *fi) {
  using namespace ghostfs::crypto;

  // Create a copy of fi without O_APPEND flag - we manage offsets ourselves
  struct fuse_file_info fi_no_append = *fi;
  fi_no_append.flags &= ~O_APPEND;

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();

    // Calculate block range first (needed for combined read optimization)
    size_t first_block = get_block_number(off);
    size_t first_block_offset = get_offset_in_block(off);
    size_t last_byte = off + size - 1;
    size_t last_block = get_block_number(last_byte);
    size_t last_block_end = get_offset_in_block(last_byte) + 1;  // exclusive
    size_t total_blocks = last_block - first_block + 1;

    // Determine which blocks need RMW (partial blocks)
    bool first_partial = (first_block_offset > 0);
    bool last_partial
        = (last_block_end < BLOCK_SIZE) && (last_block != first_block || !first_partial);
    // Special case: single partial block
    if (first_block == last_block && (first_block_offset > 0 || last_block_end < BLOCK_SIZE)) {
      first_partial = true;
      last_partial = false;
    }

    // Allocate plaintext buffer for all blocks
    std::vector<uint8_t> plaintext_buf(total_blocks * BLOCK_SIZE, 0);
    std::vector<size_t> plaintext_lens(total_blocks, BLOCK_SIZE);

    // Track if we already read the first partial block (via combined read)
    bool first_partial_already_read = false;

    // Check if we need to handle the header (file doesn't have one yet)
    {
      std::lock_guard<std::mutex> lock(g_crypto_mutex);
      auto it = g_crypto_contexts.find(fi->fh);
      if (it != g_crypto_contexts.end()) {
        // Check if file_id is all zeros (no header yet)
        bool needs_header = true;
        for (size_t i = 0; i < FILE_ID_SIZE; i++) {
          if (it->second.file_id[i] != 0) {
            needs_header = false;
            break;
          }
        }

        // Only write a new header if:
        // 1. file_id is zeros (no header read during open)
        // 2. Write starts at offset 0 (new file, not append)
        // If offset > 0, file must already exist with a header - try to read it
        if (needs_header) {
          if (off == 0) {
            // New file - write header
            uint8_t header[HEADER_SIZE];
            create_header(header);

            auto headerRequest = rpc.client->writeRequest();
            Write::Builder headerWrite = headerRequest.getReq();
            Write::FuseFileInfo::Builder headerFi = headerWrite.initFi();

            kj::ArrayPtr<kj::byte> hdr_ptr = kj::arrayPtr((kj::byte *)header, HEADER_SIZE);
            capnp::Data::Reader hdr_reader(hdr_ptr);

            headerWrite.setIno(ino);
            headerWrite.setBuf(hdr_reader);
            headerWrite.setSize(HEADER_SIZE);
            headerWrite.setOff(0);
            fillFileInfo(&headerFi, &fi_no_append);

            auto headerResult = waitWithTimeout(headerRequest.send(), timer, waitScope);
            auto headerResponse = headerResult.getRes();

            if (headerResponse.getRes() == -1) {
              std::cerr << "Failed to write encryption header" << std::endl;
              fuse_reply_err(req, headerResponse.getErrno());
              return;
            }

            std::memcpy(it->second.file_id, header + 2, FILE_ID_SIZE);
          } else {
            // Append to existing file - read header
            // Optimization: combine header read with first partial block read when possible
            // This saves one RPC round-trip
            if (first_partial && first_block == 0) {
              // Combined read: header (18 bytes) + first encrypted block (up to 4124 bytes)
              size_t combined_size = HEADER_SIZE + ENCRYPTED_BLOCK_SIZE;

              auto combinedRequest = rpc.client->readRequest();
              Read::Builder combinedRead = combinedRequest.getReq();
              Read::FuseFileInfo::Builder combinedFi = combinedRead.initFi();

              combinedRead.setIno(ino);
              combinedRead.setSize(combined_size);
              combinedRead.setOff(0);
              fillFileInfo(&combinedFi, &fi_no_append);

              auto combinedResult = waitWithTimeout(combinedRequest.send(), timer, waitScope);
              auto combinedResponse = combinedResult.getRes();

              if (combinedResponse.getRes() >= static_cast<int>(HEADER_SIZE)) {
                capnp::Data::Reader combinedBuf = combinedResponse.getBuf();
                const uint8_t *data = combinedBuf.asBytes().begin();
                size_t data_len = static_cast<size_t>(combinedResponse.getRes());

                // Parse header from first 18 bytes
                uint16_t version;
                if (parse_header(data, HEADER_SIZE, it->second.file_id, &version)) {
                  it->second.is_encrypted = true;
                }

                // Decrypt first partial block if we got enough data
                if (data_len > HEADER_SIZE) {
                  const uint8_t *block_data = data + HEADER_SIZE;
                  size_t block_len = data_len - HEADER_SIZE;
                  if (block_len >= NONCE_SIZE + TAG_SIZE) {
                    size_t dec_len;
                    if (decrypt_block(block_data, block_len, g_encryption_key, plaintext_buf.data(),
                                      &dec_len)) {
                      plaintext_lens[0] = dec_len;
                      first_partial_already_read = true;
                    }
                  }
                }
              }
            } else {
              // Just read header (partial blocks will be read separately)
              auto headerRequest = rpc.client->readRequest();
              Read::Builder headerRead = headerRequest.getReq();
              Read::FuseFileInfo::Builder headerFi = headerRead.initFi();

              headerRead.setIno(ino);
              headerRead.setSize(HEADER_SIZE);
              headerRead.setOff(0);
              fillFileInfo(&headerFi, &fi_no_append);

              auto headerResult = waitWithTimeout(headerRequest.send(), timer, waitScope);
              auto headerResponse = headerResult.getRes();

              if (headerResponse.getRes() >= static_cast<int>(HEADER_SIZE)) {
                capnp::Data::Reader headerBuf = headerResponse.getBuf();
                const uint8_t *headerData = headerBuf.asBytes().begin();
                uint16_t version;
                if (parse_header(headerData, HEADER_SIZE, it->second.file_id, &version)) {
                  it->second.is_encrypted = true;
                }
              }
            }
          }
        }
      }
    }

    const uint8_t *input = reinterpret_cast<const uint8_t *>(buf);

    // STEP 1: Read partial blocks that need RMW (skip first if already read via combined read)
    bool need_first_read = first_partial && !first_partial_already_read;
    if (need_first_read || last_partial) {
      // Determine what to read
      size_t read_first = need_first_read ? first_block : last_block;
      size_t read_last = last_partial ? last_block : (need_first_read ? first_block : last_block);
      size_t blocks_to_read = read_last - read_first + 1;

      int64_t read_start = HEADER_SIZE + read_first * ENCRYPTED_BLOCK_SIZE;
      size_t read_size = blocks_to_read * ENCRYPTED_BLOCK_SIZE;

      auto readRequest = rpc.client->readRequest();
      Read::Builder read = readRequest.getReq();
      Read::FuseFileInfo::Builder readFi = read.initFi();

      read.setIno(ino);
      read.setSize(read_size);
      read.setOff(read_start);
      fillFileInfo(&readFi, &fi_no_append);

      auto readResult = waitWithTimeout(readRequest.send(), timer, waitScope);
      auto readResponse = readResult.getRes();

      if (readResponse.getRes() > 0) {
        capnp::Data::Reader blockBuf = readResponse.getBuf();
        const uint8_t *enc_data = blockBuf.asBytes().begin();
        size_t enc_len = static_cast<size_t>(readResponse.getRes());

        // Decrypt first partial block if needed and not already read
        if (need_first_read && enc_len >= NONCE_SIZE + TAG_SIZE) {
          size_t block_enc_size = (std::min)(ENCRYPTED_BLOCK_SIZE, enc_len);
          size_t dec_len;
          if (decrypt_block(enc_data, block_enc_size, g_encryption_key, plaintext_buf.data(),
                            &dec_len)) {
            plaintext_lens[0] = dec_len;
          }
        }

        // Decrypt last partial block if needed and different from first
        if (last_partial && last_block != first_block) {
          size_t last_offset_in_read = (last_block - read_first) * ENCRYPTED_BLOCK_SIZE;
          if (last_offset_in_read < enc_len) {
            size_t block_enc_size = (std::min)(ENCRYPTED_BLOCK_SIZE, enc_len - last_offset_in_read);
            if (block_enc_size >= NONCE_SIZE + TAG_SIZE) {
              size_t dec_len;
              size_t last_plain_offset = (last_block - first_block) * BLOCK_SIZE;
              if (decrypt_block(enc_data + last_offset_in_read, block_enc_size, g_encryption_key,
                                plaintext_buf.data() + last_plain_offset, &dec_len)) {
                plaintext_lens[last_block - first_block] = dec_len;
              }
            }
          }
        }
      }
    }

    // STEP 2: Merge new data into plaintext blocks
    size_t input_offset = 0;
    for (size_t i = 0; i < total_blocks; i++) {
      size_t block_num = first_block + i;
      size_t block_start_in_write = (i == 0) ? first_block_offset : 0;
      size_t block_end_in_write = (block_num == last_block) ? last_block_end : BLOCK_SIZE;
      size_t bytes_in_block = block_end_in_write - block_start_in_write;

      uint8_t *block_ptr = plaintext_buf.data() + (i * BLOCK_SIZE);
      std::memcpy(block_ptr + block_start_in_write, input + input_offset, bytes_in_block);
      input_offset += bytes_in_block;

      // Update plaintext length if we're extending the block
      if (block_end_in_write > plaintext_lens[i]) {
        plaintext_lens[i] = block_end_in_write;
      }
    }

    // STEP 3: Encrypt all blocks (parallel for large batches using thread pool)
    std::vector<uint8_t> encrypted_buf(total_blocks * ENCRYPTED_BLOCK_SIZE);
    std::atomic<bool> encryption_failed{false};

    const size_t num_threads = std::min(total_blocks, (size_t)std::thread::hardware_concurrency());
    if (total_blocks >= 4 && num_threads > 1) {
      auto &pool = get_crypto_pool();
      std::vector<std::future<void>> futures;
      size_t blocks_per_thread = total_blocks / num_threads;
      size_t extra = total_blocks % num_threads;
      size_t start = 0;

      for (size_t t = 0; t < num_threads; t++) {
        size_t count = blocks_per_thread + (t < extra ? 1 : 0);
        futures.push_back(pool.enqueue([&, start, count]() {
          for (size_t i = 0; i < count && !encryption_failed; i++) {
            size_t idx = start + i;
            if (!encrypt_block(plaintext_buf.data() + idx * BLOCK_SIZE, plaintext_lens[idx],
                               g_encryption_key,
                               encrypted_buf.data() + idx * ENCRYPTED_BLOCK_SIZE)) {
              encryption_failed = true;
            }
          }
        }));
        start += count;
      }
      for (auto &f : futures) f.get();
    } else {
      for (size_t i = 0; i < total_blocks && !encryption_failed; i++) {
        if (!encrypt_block(plaintext_buf.data() + i * BLOCK_SIZE, plaintext_lens[i],
                           g_encryption_key, encrypted_buf.data() + i * ENCRYPTED_BLOCK_SIZE)) {
          encryption_failed = true;
        }
      }
    }

    if (encryption_failed) {
      fuse_reply_err(req, EIO);
      return;
    }

    // STEP 4: Single batch write for ALL blocks (1 RPC)
    size_t total_enc_size = total_blocks * ENCRYPTED_BLOCK_SIZE;
    int64_t phys_offset = HEADER_SIZE + first_block * ENCRYPTED_BLOCK_SIZE;

    auto writeRequest = rpc.client->writeRequest();
    Write::Builder write = writeRequest.getReq();
    Write::FuseFileInfo::Builder writeFi = write.initFi();

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte *)encrypted_buf.data(), total_enc_size);
    capnp::Data::Reader buf_reader(buf_ptr);

    write.setIno(ino);
    write.setBuf(buf_reader);
    write.setSize(total_enc_size);
    write.setOff(phys_offset);
    fillFileInfo(&writeFi, &fi_no_append);

    auto writeResult = waitWithTimeout(writeRequest.send(), timer, waitScope);
    auto writeResponse = writeResult.getRes();

    if (writeResponse.getRes() == -1) {
      fuse_reply_err(req, writeResponse.getErrno());
      return;
    }

    fuse_reply_write(req, size);

  } catch (const kj::Exception &e) {
    std::cerr << "encrypted_write error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

// Internal function that does the actual RPC read
// Returns nullopt on failure, or the response on success
std::optional<capnp::Response<GhostFS::ReadResults>> do_read_rpc(
    fuse_ino_t ino, size_t read_ahead_size, off_t off, struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->readRequest();

    Read::Builder read = request.getReq();
    Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

    read.setIno(ino);
    read.setSize(read_ahead_size);
    read.setOff(off);
    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    if (res == -1) {
      return std::nullopt;
    }

    return std::move(result);
  } catch (const kj::Exception &e) {
    std::cerr << "do_read_rpc error: " << e.getDescription().cStr() << std::endl;
    return std::nullopt;
  }
}

// Worker loop for prefetch manager - runs in dedicated threads
void PrefetchManager::worker_loop(size_t worker_id) {
  (void)worker_id;  // Can be used for debugging

  while (!shutdown.load()) {
    PrefetchRequest req;

    // Wait for work
    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      queue_cv.wait(lock, [this]() {
        return shutdown.load() || !queue.empty();
      });

      if (shutdown.load() && queue.empty()) {
        return;
      }

      if (queue.empty()) continue;

      req = queue.front();
      queue.pop();
    }

    // Get the session and block (hold shared_ptr to keep session alive)
    std::shared_ptr<PrefetchSession> sess;
    {
      std::lock_guard<std::mutex> lock(sessions_mutex);
      auto it = sessions.find(req.fh);
      if (it == sessions.end()) continue;  // Session was removed
      sess = it->second;  // Copy shared_ptr - keeps session alive
    }

    auto block = sess->get_block(req.offset);
    if (!block) continue;

    // Check if still needs fetching
    if (block->state.load(std::memory_order_acquire) != BLOCK_FETCHING) {
      continue;  // Already fetched or abandoned
    }

    // Do the RPC - worker has its own thread-local connection
    // Create a minimal fi structure with just the file handle and flags
    struct fuse_file_info fi_copy = {};
    fi_copy.fh = req.fh;
    fi_copy.flags = static_cast<int>(req.flags);

    auto result_opt = do_read_rpc(req.ino, PREFETCH_BLOCK_SIZE, req.offset, &fi_copy);

    if (!result_opt) {
      block->state.store(BLOCK_ERROR, std::memory_order_release);
      block->cv.notify_all();
      continue;
    }

    auto result = std::move(*result_opt);
    auto response = result.getRes();
    capnp::Data::Reader buf_reader = response.getBuf();
    const auto chars = buf_reader.asChars();
    size_t data_size = static_cast<size_t>(response.getRes());

    // Store data
    {
      std::lock_guard<std::mutex> lock(block->mtx);
      if (data_size > 0) {
        std::memcpy(block->data.data(), chars.begin(), data_size);
      }
      block->valid_size = data_size;
      block->state.store(BLOCK_READY, std::memory_order_release);
    }
    block->cv.notify_all();
  }
}

// Direct read - no prefetch, fetch exactly what's requested
// Used for small files and random access to avoid read amplification
void direct_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  auto result_opt = do_read_rpc(ino, size, off, fi);
  if (!result_opt) {
    fuse_reply_err(req, EIO);
    return;
  }

  auto result = std::move(*result_opt);
  auto response = result.getRes();
  int res = response.getRes();

  if (res == -1) {
    fuse_reply_err(req, response.getErrno());
    return;
  }

  capnp::Data::Reader buf_reader = response.getBuf();
  const auto chars = buf_reader.asChars();
  fuse_reply_buf(req, chars.begin(), res);
}

// Threshold for detecting large file reads (bypass SEQ_THRESHOLD)
static constexpr size_t LARGE_READ_SIZE = 64 * 1024;  // 64KB - typical FUSE read size for sequential

// Proactive read with prefetch - only used after sequential pattern is detected
void proactive_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  auto& manager = get_prefetch_manager();
  auto sess = manager.get_session(fi->fh);
  sess->ino = ino;
  sess->fh = fi->fh;
  sess->flags = static_cast<uint64_t>(fi->flags);

  // Get file size to determine if prefetch-ahead makes sense
  // Small files (< 1MB) don't benefit from 4MB block prefetch
  size_t file_size = 0;
  {
    std::shared_lock lock(g_file_size_mutex);
    auto it = g_file_sizes.find(fi->fh);
    if (it != g_file_sizes.end()) {
      file_size = it->second;
    }
  }
  // Only prefetch-ahead for large files (>= 1MB) or unknown size (could be large)
  bool should_prefetch_ahead = (file_size == 0 || file_size >= SMALL_FILE_THRESHOLD);

  // Check if sequential BEFORE recording this read
  bool was_sequential = sess->is_sequential(off);

  // Update session tracking
  sess->record_read(off, size);

  // Step 1: Always check cache first - openAndRead may have prefetched data
  // This must happen BEFORE the use_prefetch decision to serve cached small reads
  auto cached = sess->find_block(off, size);
  if (cached) {
    fuse_reply_buf(req, cached->get_data(off), size);
    if (should_prefetch_ahead) {
      manager.prefetch_ahead(ino, fi->fh, sess->flags, off);
    }
    return;
  }

  // Determine if we should use prefetch for fetching NEW data:
  // 1. Large reads (>= 64KB) indicate large file sequential access - use prefetch immediately
  // 2. For small reads, wait until we've seen SEQ_THRESHOLD bytes sequentially
  bool use_prefetch = false;

  if (size >= LARGE_READ_SIZE) {
    // Large read - likely a big file being read sequentially
    // Use prefetch immediately to avoid latency on first reads
    use_prefetch = true;
  } else {
    // Small read - check sequential pattern to avoid read amplification on small files
    size_t seq_len = sess->seq_length.load(std::memory_order_relaxed);
    use_prefetch = was_sequential && seq_len >= SEQ_THRESHOLD;
  }

  if (!use_prefetch) {
    direct_read(req, ino, size, off, fi);
    return;
  }

  // === Large read or sequential pattern detected - use prefetch system ===

  off_t aligned_off = (off / static_cast<off_t>(PREFETCH_BLOCK_SIZE)) * static_cast<off_t>(PREFETCH_BLOCK_SIZE);

  // Step 2: Check if block is being fetched by prefetch worker
  auto block = sess->get_block(aligned_off);
  {
    std::unique_lock<std::mutex> lock(block->mtx);
    int state = block->state.load(std::memory_order_acquire);

    if (state == BLOCK_FETCHING) {
      // Wait for prefetch to complete
      block->cv.wait(lock, [&block]() {
        return block->state.load(std::memory_order_acquire) != BLOCK_FETCHING;
      });
    }

    // After wait (or if not FETCHING), check if block has our data
    state = block->state.load(std::memory_order_acquire);
    if (state == BLOCK_READY && block->contains(off, size)) {
      // Serve from prefetched data (copy while holding lock for safety)
      fuse_reply_buf(req, block->get_data(off), size);
      lock.unlock();
      if (should_prefetch_ahead) {
        manager.prefetch_ahead(ino, fi->fh, sess->flags, off);
      }
      return;
    }
  }

  // Step 3: Cache miss - use direct read
  direct_read(req, ino, size, off, fi);
  if (should_prefetch_ahead) {
    manager.prefetch_ahead(ino, fi->fh, sess->flags, off);
  }
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param size -> unsigned int
 * @param off -> long int
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                            struct fuse_file_info *fi) {
  // Use encrypted read when encryption is enabled
  if (g_encryption_enabled) {
    encrypted_read(req, ino, size, off, fi);
    return;
  }

  // Fast path: Check small file cache first (minimal overhead)
  // Files fully prefetched by openAndRead are served from here
  {
    std::shared_lock lock(g_small_file_mutex);
    auto it = g_small_file_cache.find(fi->fh);
    if (it != g_small_file_cache.end()) {
      const auto& prefetch = it->second;
      if (off < static_cast<off_t>(prefetch.data.size())) {
        size_t available = prefetch.data.size() - static_cast<size_t>(off);
        size_t to_read = std::min(size, available);
        fuse_reply_buf(req, prefetch.data.data() + off, to_read);
        return;
      }
      // Read at/beyond EOF
      fuse_reply_buf(req, nullptr, 0);
      return;
    }
  }

  // Proactive prefetch read-ahead cache (disabled when max_read_ahead_cache == 0)
  // Handles cache lookup (for large files partially prefetched by openAndRead)
  // and prefetch-ahead (for sequential access patterns on large files).
  if (max_read_ahead_cache > 0) {
    proactive_read(req, ino, size, off, fi);
    return;
  }

  // Direct read - single RPC call (FUSE kernel handles read-ahead via max_readahead option)
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->readRequest();

    Read::Builder read = request.getReq();
    Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

    read.setIno(ino);
    read.setSize(size);
    read.setOff(off);

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    capnp::Data::Reader buf_reader = response.getBuf();
    const auto chars = buf_reader.asChars();
    fuse_reply_buf(req, chars.begin(), res);

  } catch (const kj::Exception &e) {
    std::cerr << "read error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

// Flush writes using bulkWriteRequest
void do_simple_flush(std::vector<cached_write>& writes) {
  if (writes.empty()) return;

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->bulkWriteRequest();

    size_t count = writes.size();
    capnp::List<Write>::Builder write_list = request.initReq(count);

    for (size_t i = 0; i < count; ++i) {
      auto& cache = writes[i];

      write_list[i].setIno(cache.ino);
      write_list[i].setOff(cache.off);
      write_list[i].setSize(cache.size);

      kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr(
        reinterpret_cast<kj::byte*>(cache.buf.get()), cache.size);
      capnp::Data::Reader buf_reader(buf_ptr);
      write_list[i].setBuf(buf_reader);

      Write::FuseFileInfo::Builder fi = write_list[i].initFi();
      fillFileInfo(&fi, &cache.fi);
    }

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    // Replies already sent - just ensure RPC completes

  } catch (const kj::Exception &e) {
    std::cerr << "do_simple_flush error: " << e.getDescription().cStr() << std::endl;
  }
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param buf -> *char
 * @param size -> unsigned int
 * @param off -> long int
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
                             off_t off, struct fuse_file_info *fi) {
  // Use encrypted write when encryption is enabled
  if (g_encryption_enabled) {
    encrypted_write(req, ino, buf, size, off, fi);
    return;
  }

  // Invalidate read caches on write (data changed)
  if (max_read_ahead_cache > 0) {
    remove_prefetch_buffer(fi->fh);
  }

  // Use async double-buffer for better throughput
  if (max_write_back_cache > 0) {
    get_write_manager().add_write(req, ino, buf, size, off, fi);
    return;
  }

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->writeRequest();

    Write::Builder write = request.getReq();
    Write::FuseFileInfo::Builder fuseFileInfo = write.initFi();

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte *)buf, size);
    capnp::Data::Reader buf_reader(buf_ptr);

    write.setIno(ino);
    write.setBuf(buf_reader);
    write.setSize(size);
    write.setOff(off);

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    fuse_reply_write(req, response.getWritten());
  } catch (const kj::Exception &e) {
    std::cerr << "write error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

static void ghostfs_ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->unlinkRequest();

    Unlink::Builder unlink = request.getReq();

    unlink.setParent(parent);
    unlink.setName(name);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    std::cerr << "unlink error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

static void ghostfs_ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->rmdirRequest();

    Rmdir::Builder rmdir = request.getReq();

    rmdir.setParent(parent);
    rmdir.setName(name);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    std::cerr << "rmdir error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

static void ghostfs_ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                               const char *name) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->symlinkRequest();

    Symlink::Builder symlink = request.getReq();

    symlink.setLink(link);
    symlink.setParent(parent);
    symlink.setName(name);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      int err = response.getErrno();
      fuse_reply_err(req, err);
    } else {
      struct fuse_entry_param e;

      memset(&e, 0, sizeof(e));
      e.ino = response.getIno();
      e.attr_timeout = 60.0;
      e.entry_timeout = 60.0;

      SymlinkResponse::Attr::Reader attributes = response.getAttr();

      e.attr.st_dev = attributes.getStDev();
      e.attr.st_ino = attributes.getStIno();
      e.attr.st_mode = attributes.getStMode();
      e.attr.st_nlink = attributes.getStNlink();
      e.attr.st_uid = geteuid();  // attributes.getStUid();
      e.attr.st_gid = getegid();  // attributes.getStGid();
      e.attr.st_rdev = attributes.getStRdev();
      e.attr.st_size = attributes.getStSize();
      e.attr.st_atime = attributes.getStAtime();
      e.attr.st_mtime = attributes.getStMtime();
      e.attr.st_ctime = attributes.getStCtime();
      e.attr.st_blksize = attributes.getStBlksize();
      e.attr.st_blocks = attributes.getStBlocks();

      fuse_reply_entry(req, &e);
    }
  } catch (const kj::Exception &e) {
    std::cerr << "symlink error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 * @param rdev -> uint16_t
 */
static void ghostfs_ll_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                             dev_t rdev) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->mknodRequest();

    Mknod::Builder mknod = request.getReq();

    mknod.setParent(parent);
    mknod.setName(name);
    mknod.setMode(mode);
    mknod.setRdev(rdev);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));
    e.ino = response.getIno();
    e.attr_timeout = 60.0;
    e.entry_timeout = 60.0;

    MknodResponse::Attr::Reader attributes = response.getAttr();

    e.attr.st_dev = attributes.getStDev();
    e.attr.st_ino = attributes.getStIno();
    e.attr.st_mode = attributes.getStMode();
    e.attr.st_nlink = attributes.getStNlink();
    e.attr.st_uid = geteuid();  // attributes.getStUid();
    e.attr.st_gid = getegid();  // attributes.getStGid();
    e.attr.st_rdev = attributes.getStRdev();
    e.attr.st_size = attributes.getStSize();
    e.attr.st_atime = attributes.getStAtime();
    e.attr.st_mtime = attributes.getStMtime();
    e.attr.st_ctime = attributes.getStCtime();
    e.attr.st_blksize = attributes.getStBlksize();
    e.attr.st_blocks = attributes.getStBlocks();

    fuse_reply_entry(req, &e);
  } catch (const kj::Exception &e) {
    std::cerr << "mknod error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param mask -> int
 */
static void ghostfs_ll_access(fuse_req_t req, fuse_ino_t ino, int mask) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->accessRequest();

    Access::Builder access = request.getReq();

    access.setIno(ino);
    access.setMask(mask);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
    } else {
      fuse_reply_err(req, 0);
    }
  } catch (const kj::Exception &e) {
    std::cerr << "access error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                              struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->createRequest();

    Create::Builder create = request.getReq();
    Create::FuseFileInfo::Builder fuseFileInfo = create.initFi();

    create.setParent(parent);
    create.setName(name);
    create.setMode(mode);

    // For encrypted files:
    // 1. Strip O_APPEND - Linux's pwrite() with O_APPEND ignores offset
    // 2. Ensure O_RDWR for RMW operations (partial block writes need to read existing data)
    struct fuse_file_info fi_for_server = *fi;
    if (g_encryption_enabled) {
      fi_for_server.flags &= ~O_APPEND;
      // If file was opened write-only, upgrade to read-write for RMW support
      if ((fi_for_server.flags & O_ACCMODE) == O_WRONLY) {
        fi_for_server.flags = (fi_for_server.flags & ~O_ACCMODE) | O_RDWR;
      }
    }
    fillFileInfo(&fuseFileInfo, &fi_for_server);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    struct stat attr;

    memset(&attr, 0, sizeof(attr));

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));
    e.ino = response.getIno();
    e.attr_timeout = 60.0;
    e.entry_timeout = 60.0;

    CreateResponse::Attr::Reader attributes = response.getAttr();

    e.attr.st_dev = attributes.getStDev();
    e.attr.st_ino = attributes.getStIno();
    e.attr.st_mode = attributes.getStMode();
    e.attr.st_nlink = attributes.getStNlink();
    e.attr.st_uid = geteuid();  // attributes.getStUid();
    e.attr.st_gid = getegid();  // attributes.getStGid();
    e.attr.st_rdev = attributes.getStRdev();
    e.attr.st_size = attributes.getStSize();
    e.attr.st_atime = attributes.getStAtime();
    e.attr.st_mtime = attributes.getStMtime();
    e.attr.st_ctime = attributes.getStCtime();
    e.attr.st_blksize = attributes.getStBlksize();
    e.attr.st_blocks = attributes.getStBlocks();

    CreateResponse::FuseFileInfo::Reader fi_response = response.getFi();

    fi->fh = fi_response.getFh();

    // Write encryption header for new files
    if (g_encryption_enabled) {
      uint8_t header[ghostfs::crypto::HEADER_SIZE];
      ghostfs::crypto::create_header(header);

      // Write header to file via RPC
      auto writeRequest = rpc.client->writeRequest();
      Write::Builder write = writeRequest.getReq();
      Write::FuseFileInfo::Builder writeFi = write.initFi();

      kj::ArrayPtr<kj::byte> buf_ptr
          = kj::arrayPtr((kj::byte *)header, ghostfs::crypto::HEADER_SIZE);
      capnp::Data::Reader buf_reader(buf_ptr);

      write.setIno(e.ino);
      write.setBuf(buf_reader);
      write.setSize(ghostfs::crypto::HEADER_SIZE);
      write.setOff(0);
      fillFileInfo(&writeFi, fi);

      auto writeResult = waitWithTimeout(writeRequest.send(), timer, waitScope);
      auto writeResponse = writeResult.getRes();

      if (writeResponse.getRes() == -1) {
        std::cerr << "Failed to write encryption header" << std::endl;
        fuse_reply_err(req, writeResponse.getErrno());
        return;
      }

      // Initialize crypto context
      {
        std::lock_guard<std::mutex> lock(g_crypto_mutex);
        ghostfs::crypto::FileContext ctx;
        ctx.is_encrypted = true;
        ctx.plaintext_size = 0;  // New file, empty
        std::memcpy(ctx.file_id, header + 2, ghostfs::crypto::FILE_ID_SIZE);
        g_crypto_contexts[fi->fh] = ctx;
      }

      // Report size as 0 (logical size) since we just created it
      e.attr.st_size = 0;
    }

    fuse_reply_create(req, &e, fi);
  } catch (const kj::Exception &ex) {
    std::cerr << "create error: " << ex.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 */
static void ghostfs_ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->mkdirRequest();

    Mkdir::Builder mkdir = request.getReq();

    mkdir.setParent(parent);
    mkdir.setName(name);
    mkdir.setMode(mode);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));
    e.ino = response.getIno();
    e.attr_timeout = 60.0;
    e.entry_timeout = 60.0;

    MkdirResponse::Attr::Reader attributes = response.getAttr();

    e.attr.st_dev = attributes.getStDev();
    e.attr.st_ino = attributes.getStIno();
    e.attr.st_mode = attributes.getStMode();
    e.attr.st_nlink = attributes.getStNlink();
    e.attr.st_uid = geteuid();  // attributes.getStUid();
    e.attr.st_gid = getegid();  // attributes.getStGid();
    e.attr.st_rdev = attributes.getStRdev();
    e.attr.st_size = attributes.getStSize();
    e.attr.st_atime = attributes.getStAtime();
    e.attr.st_mtime = attributes.getStMtime();
    e.attr.st_ctime = attributes.getStCtime();
    e.attr.st_blksize = attributes.getStBlksize();
    e.attr.st_blocks = attributes.getStBlocks();

    fuse_reply_entry(req, &e);
  } catch (const kj::Exception &e) {
    std::cerr << "mkdir error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

static void ghostfs_ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                              fuse_ino_t newparent, const char *newname) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->renameRequest();

    Rename::Builder rename = request.getReq();

    rename.setParent(parent);
    rename.setName(name);
    rename.setNewparent(newparent);
    rename.setNewname(newname);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    std::cerr << "rename error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 */
static void ghostfs_ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  // Flush any pending writes before releasing the file handle
  get_write_manager().flush_fh(fi->fh);

  // Cleanup prefetch buffer (handles both openAndRead prefetch and proactive prefetch)
  remove_prefetch_buffer(fi->fh);

  // Cleanup file size tracking
  {
    std::unique_lock lock(g_file_size_mutex);
    g_file_sizes.erase(fi->fh);
  }

  // Cleanup small file cache
  {
    std::unique_lock lock(g_small_file_mutex);
    g_small_file_cache.erase(fi->fh);
  }

  // Cleanup crypto context
  if (g_encryption_enabled) {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    g_crypto_contexts.erase(fi->fh);
  }

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->releaseRequest();

    Release::Builder release = request.getReq();
    Release::FuseFileInfo::Builder fuseFileInfo = release.initFi();

    release.setIno(ino);
    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    // Peer disconnect during release is expected during shutdown - reply success
    // since the file handle is being closed anyway
    if (e.getType() == kj::Exception::Type::DISCONNECTED) {
      fuse_reply_err(req, 0);
    } else {
      std::cerr << "release error: " << e.getDescription().cStr() << std::endl;
      fuse_reply_err(req, ETIMEDOUT);
    }
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 */
static void ghostfs_ll_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  get_write_manager().flush_fh(fi->fh);

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->flushRequest();

    Flush::Builder flush = request.getReq();
    Flush::FuseFileInfo::Builder fuseFileInfo = flush.initFi();

    flush.setIno(ino);
    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    // Peer disconnect during flush is expected during shutdown
    if (e.getType() == kj::Exception::Type::DISCONNECTED) {
      fuse_reply_err(req, 0);
    } else {
      std::cerr << "flush error: " << e.getDescription().cStr() << std::endl;
      fuse_reply_err(req, ETIMEDOUT);
    }
  }
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 * @param mode -> uint64_t
 */
static void ghostfs_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
                             struct fuse_file_info *fi) {
  get_write_manager().flush_fh(fi->fh);

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->fsyncRequest();

    Fsync::Builder fsync = request.getReq();
    Fsync::FuseFileInfo::Builder fuseFileInfo = fsync.initFi();

    fsync.setIno(ino);
    fsync.setDatasync(datasync);

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();
    int err = response.getErrno();

    fuse_reply_err(req, res == -1 ? err : 0);
  } catch (const kj::Exception &e) {
    std::cerr << "fsync error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param attr -> {
 *    uint16_t      st_dev
 *    uint64_t      st_ino
 *    uint64_t      st_mode
 *    uint16_t      st_nlink
 *             int  st_uid
 *             int  st_gid
 *    uint16_t      st_rdev
 *    long     int  st_size
 *    int64_t       st_atime
 *    int64_t       st_mtime
 *    int64_t       st_ctime
 *    uint64_t      st_blksize
 *    uint64_t      st_blocks
 * }
 * @param to_set -> int64_t
 * @param fi -> {
 *             int 	flags
 *    unsigned int 	writepage
 *    unsigned int 	direct_io
 *    unsigned int 	keep_cache
 *    unsigned int 	flush
 *    unsigned int 	nonseekable
 *    unsigned int 	cache_readdir
 *    unsigned int 	padding
 *    uint64_t 	    fh
 *    uint64_t 	    lock_owner
 *    uint32_t 	    poll_events
 *    unsigned int 	noflush
 * }
 */
static void ghostfs_ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set,
                               struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->setattrRequest();

    Setattr::Builder setattr = request.getReq();
    Setattr::FuseFileInfo::Builder fuseFileInfo = setattr.initFi();
    Setattr::Attr::Builder attributes = setattr.initAttr();

    Setattr::Attr::TimeSpec::Builder stAtime = attributes.initStAtime();
    Setattr::Attr::TimeSpec::Builder stMtime = attributes.initStMtime();

    setattr.setIno(ino);
    setattr.setToSet(to_set);

    attributes.setStDev(attr->st_dev);
    attributes.setStIno(attr->st_ino);
    attributes.setStMode(attr->st_mode);
    attributes.setStNlink(attr->st_nlink);
    attributes.setStUid(attr->st_uid);
    attributes.setStGid(attr->st_gid);
    attributes.setStRdev(attr->st_rdev);

    // Translate logical size to physical size for encrypted files during truncate
    int64_t size_to_set = attr->st_size;
    if (g_encryption_enabled && (to_set & FUSE_SET_ATTR_SIZE)) {
      size_to_set = ghostfs::crypto::logical_to_physical_size(attr->st_size);
    }
    attributes.setStSize(size_to_set);
    attributes.setStCtime(attr->st_ctime);
    attributes.setStBlksize(attr->st_blksize);
    attributes.setStBlocks(attr->st_blocks);

    // clang-format off
    #if defined(__APPLE__)
      stAtime.setTvSec(attr->st_atimespec.tv_sec);
      stAtime.setTvNSec(attr->st_atimespec.tv_nsec);
      stMtime.setTvSec(attr->st_mtimespec.tv_sec);
      stMtime.setTvNSec(attr->st_mtimespec.tv_nsec);
    #else
      stAtime.setTvSec(attr->st_atim.tv_sec);
      stAtime.setTvNSec(attr->st_atim.tv_nsec);
      stMtime.setTvSec(attr->st_mtim.tv_sec);
      stMtime.setTvNSec(attr->st_mtim.tv_nsec);
    #endif

    fillFileInfo(&fuseFileInfo, fi);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    ghostfs_ll_getattr(req, response.getIno(), fi);
  } catch (const kj::Exception& e) {
    std::cerr << "setattr error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

#ifdef __APPLE__
static void ghostfs_ll_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value,
                              size_t size, int flags, uint32_t position) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->setxattrRequest();

    Setxattr::Builder setxattr = request.getReq();

    setxattr.setIno(ino);
    setxattr.setName(name);
    setxattr.setValue(value);
    setxattr.setSize(size);
    setxattr.setFlags(flags);
    setxattr.setPosition(position);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }
  } catch (const kj::Exception& e) {
    std::cerr << "setxattr error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}
#endif

static void ghostfs_ll_readlink(fuse_req_t req, fuse_ino_t ino) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->readlinkRequest();

    Readlink::Builder readlink = request.getReq();

    readlink.setIno(ino);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    int res = response.getRes();

    if (res == -1) {
      int err = response.getErrno();
      fuse_reply_err(req, err);
    } else {
      std::string link = response.getLink();
      fuse_reply_readlink(req, link.c_str());
    }
  } catch (const kj::Exception& e) {
    std::cerr << "readlink error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

// FUSE init - set capabilities for better performance
static void ghostfs_ll_init(void *userdata, struct fuse_conn_info *conn) {
  (void)userdata;

  // Request async reads for better pipelining (kernel issues multiple reads concurrently)
  if (conn->capable & FUSE_CAP_ASYNC_READ) {
    conn->want |= FUSE_CAP_ASYNC_READ;
  }

  // Enable big writes (single writes larger than 4KB)
  if (conn->capable & FUSE_CAP_BIG_WRITES) {
    conn->want |= FUSE_CAP_BIG_WRITES;
  }

  // Increase background request limits for higher parallelism
  // These control how many concurrent FUSE requests the kernel can have in flight
  // Default is typically 12, which limits throughput on high-latency connections
  conn->max_background = 256;        // Allow many concurrent background requests
  conn->congestion_threshold = 200;  // Start throttling new requests at this level

  // Note: We do NOT modify conn->max_write or conn->max_readahead here.
  // Setting these values causes "Invalid argument" errors in some Docker
  // environments. Use mount options (-o max_read=N, -o max_readahead=N)
  // to request larger buffers, which works in environments where FUSE
  // properly supports those values.

  // Note: FUSE_CAP_SPLICE_* capabilities are NOT explicitly requested.
  // Per libfuse docs, splice is enabled by default when supported by the
  // kernel AND the filesystem implements write_buf()/read_buf() handlers.
  // Since we don't implement those handlers, splice won't be used.
}

// clang-format off
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static const struct fuse_lowlevel_ops ghostfs_ll_oper = {
    .init = ghostfs_ll_init,
    .lookup = ghostfs_ll_lookup,
    .getattr = ghostfs_ll_getattr,
    .setattr = ghostfs_ll_setattr,
    .readlink = ghostfs_ll_readlink,
    .mknod = ghostfs_ll_mknod,
    .mkdir = ghostfs_ll_mkdir,
    .unlink = ghostfs_ll_unlink,
    .rmdir = ghostfs_ll_rmdir,
    .symlink = ghostfs_ll_symlink,
    .rename = ghostfs_ll_rename,
    .open = ghostfs_ll_open,
    .read = ghostfs_ll_read,
    .write = ghostfs_ll_write,
    .flush = ghostfs_ll_flush,
    .release = ghostfs_ll_release,
    .fsync = ghostfs_ll_fsync,
    .readdir = ghostfs_ll_readdir,
    #ifdef __APPLE__
      .setxattr = ghostfs_ll_setxattr,
    #endif
    .access = ghostfs_ll_access,
    .create = ghostfs_ll_create,
};
#pragma GCC diagnostic pop
// clang-format on

std::string read_file(const std::string &path);

// Encryption helper functions
void set_encryption_enabled(bool enabled) { g_encryption_enabled = enabled; }

bool is_encryption_enabled() { return g_encryption_enabled; }

bool load_encryption_key(const std::string &key_path) {
  return ghostfs::crypto::load_key_file(key_path, g_encryption_key);
}

void free_capnp_resources() {
  // Thread-local Cap'n Proto resources are cleaned up automatically
  // when threads exit. Nothing to do here.
}

void capnpErrorHandler(kj::Exception &e) {
  std::cout << "Error: " << e.getDescription().cStr() << std::endl;
  free_capnp_resources();
  exit(1);
}

#define CATCH_OWN(TYPE)                                         \
  [](kj::Exception &&exception) -> kj::Promise<kj::Own<TYPE>> { \
    capnpErrorHandler(exception);                               \
    return nullptr;                                             \
  }

#define CATCH_RESPONSE(TYPE)                                            \
  [](kj::Exception &&exception) -> kj::Promise<capnp::Response<TYPE>> { \
    capnpErrorHandler(exception);                                       \
    return nullptr;                                                     \
  }

int start_fs(char *executable, char *argmnt, std::vector<std::string> options, std::string host,
             int port, std::string user, std::string token, uint8_t write_back_cache_size,
             uint8_t read_ahead_cache_size, std::string cert_file, bool use_tls) {
  kj::_::Debug::setLogLevel(kj::_::Debug::Severity::INFO);

  // Set cache sizes from parameters (now thread-safe with mutex protection)
  max_write_back_cache = write_back_cache_size;
  max_read_ahead_cache = read_ahead_cache_size;

  std::string cert = cert_file.length() ? read_file(cert_file) : "";

  // Store connection parameters for thread-local client creation
  g_conn_params.host = host;
  g_conn_params.port = port;
  g_conn_params.user = user;
  g_conn_params.token = token;
  g_conn_params.cert = cert;
  g_conn_params.use_tls = use_tls;

  // Verify credentials by doing initial authentication on main thread
  try {
    (void)getRpc();
    std::cout << "Connected to the GhostFS server." << std::endl;
  } catch (const std::exception &e) {
    std::cout << "Authentication failed: " << e.what() << std::endl;
    return 1;
  }

  char *argv[2] = {executable, argmnt};
  int err = -1;
  char *mountpoint;

  struct fuse_args args = FUSE_ARGS_INIT(2, argv);
  err = fuse_parse_cmdline(&args, &mountpoint, NULL, NULL);

  if (err == -1) {
    std::cout << "There was an issue parsing fuse options" << std::endl;
    free_capnp_resources();
    return err;
  }

  for (std::string option : options) {
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, option.c_str());
  }

  struct fuse_chan *ch = fuse_mount(mountpoint, &args);

  if (ch == NULL) {
    std::cout << "There was an error mounting the fuse endpoint" << std::endl;
    free_capnp_resources();
    return -1;
  }

  struct fuse_session *se
      = fuse_lowlevel_new(&args, &ghostfs_ll_oper, sizeof(ghostfs_ll_oper), NULL);

  if (se != NULL) {
    if (fuse_set_signal_handlers(se) != -1) {
      std::cout << "Mounted the GhostFS endpoint." << std::endl;
      fuse_session_add_chan(se, ch);
      // Use multi-threaded loop to handle concurrent FUSE requests
      // (needed for following symlinks that point back to the same mount)
      err = fuse_session_loop_mt(se);
      std::cout << "Unmounting GhostFS..." << std::endl;
      fuse_remove_signal_handlers(se);
      fuse_session_remove_chan(ch);
    }
    fuse_session_destroy(se);
  }

  fuse_unmount(mountpoint, ch);
  fuse_opt_free_args(&args);
  free_capnp_resources();

  std::cout << "GhostFS unmounted." << std::endl;
  return err ? 1 : 0;
}
