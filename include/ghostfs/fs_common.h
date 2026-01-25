#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Cap'n Proto forward declarations
#include <capnp/rpc-twoparty.h>
#include <kj/async-io.h>
#include <ghostfs.capnp.h>

namespace ghostfs {

// Timeout constants (milliseconds)
constexpr uint64_t CONNECTION_TIMEOUT_MS = 5000;   // 5 seconds for connection
constexpr uint64_t RPC_TIMEOUT_MS = 30000;         // 30 seconds for RPC calls

// Maximum read-ahead buffer size to prevent memory explosion (16MB)
constexpr size_t MAX_READ_AHEAD_BYTES = 16 * 1024 * 1024;

// Cache size configuration
extern uint8_t max_write_back_cache;
extern uint8_t max_read_ahead_cache;

// Global connection parameters for thread-local client creation
struct ConnectionParams {
  std::string host;
  int port;
  std::string user;
  std::string token;
  std::string cert;
};
extern ConnectionParams g_conn_params;


// Thread-local Cap'n Proto state
struct ThreadLocalRpc {
  std::unique_ptr<kj::AsyncIoContext> ioContext;
  std::unique_ptr<capnp::TwoPartyClient> twoParty;
  kj::Own<kj::AsyncIoStream> connection;
  std::optional<GhostFS::Client> client;
  bool initialized = false;

  kj::Timer& getTimer();
  void init();
};

extern thread_local ThreadLocalRpc tl_rpc;

// Helper to get thread-local RPC client
ThreadLocalRpc& getRpc();

// Helper for RPC calls with timeout
template<typename Promise>
auto waitWithTimeout(Promise&& promise, kj::Timer& timer, kj::WaitScope& waitScope)
    -> decltype(kj::fwd<Promise>(promise).wait(waitScope)) {
  using ResultType = decltype(kj::fwd<Promise>(promise).wait(waitScope));
  auto timeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
      .then([]() -> ResultType {
        KJ_FAIL_REQUIRE("RPC timeout");
      });
  return kj::fwd<Promise>(promise).exclusiveJoin(kj::mv(timeout)).wait(waitScope);
}

// Write cache structure (platform-independent part)
struct CachedWriteBase {
  uint64_t ino;
  char *buf;
  size_t size;
  int64_t off;
  uint64_t fh;
  int flags;
};

// Read cache structure (platform-independent)
struct CachedReadBase {
  uint64_t ino;
  char *buf;
  size_t size;
  int64_t off;
  uint64_t fh;
};

// Cache containers
extern std::map<uint64_t, std::vector<CachedWriteBase>> write_back_cache;
extern std::map<uint64_t, CachedReadBase> read_ahead_cache;

// Cache mutexes
extern std::mutex write_cache_mutex;
extern std::mutex read_cache_mutex;

// Cache operations
uint64_t add_to_write_back_cache(CachedWriteBase cache);

// Check if read can be served from cache; returns bytes copied or 0 if not cached
size_t try_read_from_cache(uint64_t fh, size_t size, int64_t off, char* out_buf);

// Clear read cache entry for a file handle
void invalidate_read_cache(uint64_t fh);

// Utility functions
std::string read_file(const std::string& path);
void free_capnp_resources();

// Helper to fill fuse file info into Cap'n Proto message
template <class T>
void fillFileInfoCommon(T *fuseFileInfo, int flags, int writepage, int direct_io,
                        int keep_cache, int flush, int nonseekable, int padding,
                        uint64_t fh, uint64_t lock_owner) {
  fuseFileInfo->setFlags(flags);
  fuseFileInfo->setWritepage(writepage);
  fuseFileInfo->setDirectIo(direct_io);
  fuseFileInfo->setKeepCache(keep_cache);
  fuseFileInfo->setFlush(flush);
  fuseFileInfo->setNonseekable(nonseekable);
  fuseFileInfo->setPadding(padding);
  fuseFileInfo->setFh(fh);
  fuseFileInfo->setLockOwner(lock_owner);
}

// Initialize connection parameters and verify authentication
bool init_connection(const std::string& host, int port, const std::string& user,
                     const std::string& token, const std::string& cert_file,
                     uint8_t write_back_size, uint8_t read_ahead_size);

} // namespace ghostfs
