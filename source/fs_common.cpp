#include <ghostfs/fs_common.h>

#include <cstring>
#include <fstream>
#include <iostream>

#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/serialize-packed.h>
#include <kj/async-io.h>
#include <kj/async.h>
#include <kj/compat/tls.h>

#include <ghostfs.capnp.h>

namespace ghostfs {

// Global variables
uint8_t max_write_back_cache = 8;
uint8_t max_read_ahead_cache = 8;

ConnectionParams g_conn_params;

std::map<uint64_t, std::vector<CachedWriteBase>> write_back_cache;
std::map<uint64_t, CachedReadBase> read_ahead_cache;

std::mutex write_cache_mutex;
std::mutex read_cache_mutex;

thread_local ThreadLocalRpc tl_rpc;

// ThreadLocalRpc implementation
kj::Timer& ThreadLocalRpc::getTimer() {
  return ioContext->provider->getTimer();
}

void ThreadLocalRpc::init() {
  if (initialized) return;

  ioContext = std::make_unique<kj::AsyncIoContext>(kj::setupAsyncIo());
  auto& timer = ioContext->provider->getTimer();

  if (g_conn_params.cert.length()) {
    kj::TlsContext::Options options;
    kj::TlsCertificate caCert(g_conn_params.cert);
    options.trustedCertificates = kj::arrayPtr(&caCert, 1);

    kj::TlsContext tls(kj::mv(options));
    auto network = tls.wrapNetwork(ioContext->provider->getNetwork());

    // DNS resolution with timeout
    auto addressPromise = network->parseAddress(g_conn_params.host, g_conn_params.port);
    auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
        .then([]() -> kj::Own<kj::NetworkAddress> {
          KJ_FAIL_REQUIRE("DNS resolution timed out");
        });
    auto address = addressPromise.exclusiveJoin(kj::mv(addressTimeout))
        .wait(ioContext->waitScope);

    // TCP connection with timeout
    auto connectPromise = address->connect();
    auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
        .then([]() -> kj::Own<kj::AsyncIoStream> {
          KJ_FAIL_REQUIRE("Connection timed out");
        });
    connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout))
        .wait(ioContext->waitScope);
  } else {
    // DNS resolution with timeout
    auto addressPromise = ioContext->provider->getNetwork()
        .parseAddress(g_conn_params.host, g_conn_params.port);
    auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
        .then([]() -> kj::Own<kj::NetworkAddress> {
          KJ_FAIL_REQUIRE("DNS resolution timed out");
        });
    auto address = addressPromise.exclusiveJoin(kj::mv(addressTimeout))
        .wait(ioContext->waitScope);

    // TCP connection with timeout
    auto connectPromise = address->connect();
    auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
        .then([]() -> kj::Own<kj::AsyncIoStream> {
          KJ_FAIL_REQUIRE("Connection timed out");
        });
    connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout))
        .wait(ioContext->waitScope);
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
  auto result = authPromise.exclusiveJoin(kj::mv(authTimeout))
      .wait(ioContext->waitScope);

  if (!result.getAuthSuccess()) {
    throw std::runtime_error("Thread-local authentication failed");
  }

  client = result.getGhostFs();
  initialized = true;
}

// Helper to get thread-local RPC client
ThreadLocalRpc& getRpc() {
  tl_rpc.init();
  return tl_rpc;
}

// Cache operations
uint64_t add_to_write_back_cache(CachedWriteBase cache) {
  std::lock_guard<std::mutex> lock(write_cache_mutex);

  if (write_back_cache.find(cache.fh) == write_back_cache.end()) {
    write_back_cache[cache.fh] = std::vector<CachedWriteBase>();
  }

  write_back_cache[cache.fh].push_back(cache);
  return write_back_cache[cache.fh].size();
}

size_t try_read_from_cache(uint64_t fh, size_t size, int64_t off, char* out_buf) {
  std::lock_guard<std::mutex> lock(read_cache_mutex);

  auto it = read_ahead_cache.find(fh);
  if (it == read_ahead_cache.end()) {
    return 0;
  }

  CachedReadBase& cache = it->second;

  if (cache.off > off) {
    return 0;
  }

  int64_t cache_end = cache.off + static_cast<int64_t>(cache.size);
  int64_t read_end = off + static_cast<int64_t>(size);

  if (read_end > cache_end) {
    return 0;
  }

  memcpy(out_buf, cache.buf + (off - cache.off), size);
  return size;
}

void invalidate_read_cache(uint64_t fh) {
  std::lock_guard<std::mutex> lock(read_cache_mutex);

  auto it = read_ahead_cache.find(fh);
  if (it != read_ahead_cache.end()) {
    free(it->second.buf);
    read_ahead_cache.erase(it);
  }
}

// Utility functions
std::string read_file(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open file: " + path);
  }
  return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void free_capnp_resources() {
  // Thread-local Cap'n Proto resources are cleaned up automatically
  // when threads exit. Nothing to do here.
}

bool init_connection(const std::string& host, int port, const std::string& user,
                     const std::string& token, const std::string& cert_file,
                     uint8_t write_back_size, uint8_t read_ahead_size) {
  // Set cache sizes from parameters
  max_write_back_cache = write_back_size;
  max_read_ahead_cache = read_ahead_size;

  std::string cert = cert_file.length() ? read_file(cert_file) : "";

  // Store connection parameters for thread-local client creation
  g_conn_params.host = host;
  g_conn_params.port = port;
  g_conn_params.user = user;
  g_conn_params.token = token;
  g_conn_params.cert = cert;

  // Verify credentials by doing initial authentication on main thread
  try {
    (void)getRpc();
    std::cout << "Connected to the GhostFS server." << std::endl;
    return true;
  } catch (const std::exception& e) {
    std::cout << "Authentication failed: " << e.what() << std::endl;
    return false;
  }
}

} // namespace ghostfs
