#include <fcntl.h>
#include <ghostfs/copy.h>
#include <ghostfs/crypto.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

// Cap'n Proto
#include <bulkread.capnp.h>
#include <bulkread.response.capnp.h>
#include <bulkupload.capnp.h>
#include <bulkupload.response.capnp.h>
#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <copyfile.capnp.h>
#include <copyfile.response.capnp.h>
#include <ghostfs.capnp.h>
#include <kj/async-io.h>
#include <kj/compat/tls.h>

namespace ghostfs {

  // Chunk size for bulk transfers (4MB)
  constexpr size_t CHUNK_SIZE = 4 * 1024 * 1024;

  // Timeout constants (milliseconds)
  constexpr uint64_t CONNECTION_TIMEOUT_MS = 10000;  // 10 seconds for connection
  constexpr uint64_t RPC_TIMEOUT_MS = 120000;        // 2 minutes for bulk RPC calls

  // Encryption state for copy operations
  static bool g_copy_encryption_enabled = false;
  static uint8_t g_copy_encryption_key[crypto::KEY_SIZE];

  // GhostFS path prefix
  constexpr const char* GFS_PREFIX = "gfs:";
  constexpr size_t GFS_PREFIX_LEN = 4;

  static bool is_gfs_path(const std::string& path) {
    return path.size() > GFS_PREFIX_LEN && path.substr(0, GFS_PREFIX_LEN) == GFS_PREFIX;
  }

  static std::string strip_gfs_prefix(const std::string& path) {
    if (is_gfs_path(path)) {
      return path.substr(GFS_PREFIX_LEN);
    }
    return path;
  }

  // Progress display
  static void display_progress(int64_t current, int64_t total, bool show_progress) {
    if (!show_progress || total == 0) return;

    int percent = static_cast<int>((current * 100) / total);
    int bar_width = 40;
    int filled = (percent * bar_width) / 100;

    std::cout << "\r[";
    for (int i = 0; i < bar_width; ++i) {
      if (i < filled)
        std::cout << "=";
      else if (i == filled)
        std::cout << ">";
      else
        std::cout << " ";
    }

    double current_mb = current / (1024.0 * 1024.0);
    double total_mb = total / (1024.0 * 1024.0);

    std::cout << "] " << percent << "% (" << std::fixed << std::setprecision(1) << current_mb << "/"
              << total_mb << " MB)" << std::flush;

    if (current >= total) {
      std::cout << std::endl;
    }
  }

  // Upload local file to GhostFS
  static int copy_upload(const CopyConfig& config) {
    std::string local_path = config.source;
    std::string remote_path = strip_gfs_prefix(config.destination);

    // Remove leading slash if present
    if (!remote_path.empty() && remote_path[0] == '/') {
      remote_path = remote_path.substr(1);
    }

    // Open local file
    int fd = ::open(local_path.c_str(), O_RDONLY);
    if (fd == -1) {
      std::cerr << "Error: Cannot open local file: " << local_path << " (" << strerror(errno) << ")"
                << std::endl;
      return 1;
    }

    // Get file size
    struct stat st;
    if (::fstat(fd, &st) == -1) {
      std::cerr << "Error: Cannot stat local file: " << strerror(errno) << std::endl;
      ::close(fd);
      return 1;
    }
    int64_t total_size = st.st_size;
    mode_t file_mode = st.st_mode & 0777;

    // Setup RPC connection
    auto ioContext = kj::setupAsyncIo();
    auto& timer = ioContext.provider->getTimer();

    kj::Own<kj::AsyncIoStream> connection;

    // DNS resolution with timeout
    auto addressPromise = ioContext.provider->getNetwork().parseAddress(config.host, config.port);
    auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::NetworkAddress> {
                                KJ_FAIL_REQUIRE("DNS resolution timed out");
                              });
    auto address = addressPromise.exclusiveJoin(kj::mv(addressTimeout)).wait(ioContext.waitScope);

    // TCP connection with timeout
    auto connectPromise = address->connect();
    auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::AsyncIoStream> {
                                KJ_FAIL_REQUIRE("Connection timed out");
                              });
    connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout)).wait(ioContext.waitScope);

    capnp::TwoPartyClient twoParty(*connection);
    auto rpcCapability = twoParty.bootstrap();
    auto authClient = rpcCapability.castAs<GhostFSAuth>();

    auto authRequest = authClient.authRequest();
    authRequest.setUser(config.user);
    authRequest.setToken(config.token);

    // Auth RPC with timeout
    auto authPromise = authRequest.send();
    auto authTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                           .then([]() -> capnp::Response<GhostFSAuth::AuthResults> {
                             KJ_FAIL_REQUIRE("Authentication timed out");
                           });
    auto authResult = authPromise.exclusiveJoin(kj::mv(authTimeout)).wait(ioContext.waitScope);

    if (!authResult.getAuthSuccess()) {
      std::cerr << "Error: Authentication failed" << std::endl;
      ::close(fd);
      return 1;
    }

    auto client = authResult.getGhostFs();

    std::vector<char> buf(CHUNK_SIZE);
    int64_t offset = 0;
    bool first_chunk = true;

    while (offset < total_size || (total_size == 0 && first_chunk)) {
      ssize_t bytes_read = ::pread(fd, buf.data(), CHUNK_SIZE, offset);
      if (bytes_read <= 0) {
        if (bytes_read == 0 && offset > 0) break;  // EOF
        if (bytes_read < 0) {
          std::cerr << "Error reading local file: " << strerror(errno) << std::endl;
          ::close(fd);
          return 1;
        }
      }

      // Non-encrypted upload
      auto request = client.bulkUploadRequest();
      auto req = request.initReq();
      req.setPath(remote_path);
      req.setOffset(offset);
      req.setTruncate(first_chunk);
      req.setMode(file_mode);

      kj::ArrayPtr<const kj::byte> data_ptr(reinterpret_cast<const kj::byte*>(buf.data()),
                                            bytes_read);
      req.setBuf(data_ptr);

      auto uploadPromise = request.send();
      auto uploadTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                               .then([]() -> capnp::Response<GhostFS::BulkUploadResults> {
                                 KJ_FAIL_REQUIRE("Upload timed out");
                               });
      auto result = uploadPromise.exclusiveJoin(kj::mv(uploadTimeout)).wait(ioContext.waitScope);

      if (result.getRes().getRes() != 0) {
        std::cerr << "Error: Upload failed with errno "
                  << static_cast<int>(result.getRes().getErrno()) << std::endl;
        ::close(fd);
        return 1;
      }

      offset += bytes_read;
      first_chunk = false;

      display_progress(offset, total_size, config.show_progress);
    }

    ::close(fd);

    if (!config.show_progress) {
      std::cout << "Uploaded " << total_size << " bytes to " << config.destination << std::endl;
    }

    return 0;
  }

  // Download GhostFS file to local
  static int copy_download(const CopyConfig& config) {
    std::string remote_path = strip_gfs_prefix(config.source);
    std::string local_path = config.destination;

    // Remove leading slash if present
    if (!remote_path.empty() && remote_path[0] == '/') {
      remote_path = remote_path.substr(1);
    }

    // Setup RPC connection
    auto ioContext = kj::setupAsyncIo();
    auto& timer = ioContext.provider->getTimer();

    kj::Own<kj::AsyncIoStream> connection;

    // DNS resolution with timeout
    auto addressPromise = ioContext.provider->getNetwork().parseAddress(config.host, config.port);
    auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::NetworkAddress> {
                                KJ_FAIL_REQUIRE("DNS resolution timed out");
                              });
    auto address = addressPromise.exclusiveJoin(kj::mv(addressTimeout)).wait(ioContext.waitScope);

    // TCP connection with timeout
    auto connectPromise = address->connect();
    auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::AsyncIoStream> {
                                KJ_FAIL_REQUIRE("Connection timed out");
                              });
    connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout)).wait(ioContext.waitScope);

    capnp::TwoPartyClient twoParty(*connection);
    auto rpcCapability = twoParty.bootstrap();
    auto authClient = rpcCapability.castAs<GhostFSAuth>();

    auto authRequest = authClient.authRequest();
    authRequest.setUser(config.user);
    authRequest.setToken(config.token);

    // Auth RPC with timeout
    auto authPromise = authRequest.send();
    auto authTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                           .then([]() -> capnp::Response<GhostFSAuth::AuthResults> {
                             KJ_FAIL_REQUIRE("Authentication timed out");
                           });
    auto authResult = authPromise.exclusiveJoin(kj::mv(authTimeout)).wait(ioContext.waitScope);

    if (!authResult.getAuthSuccess()) {
      std::cerr << "Error: Authentication failed" << std::endl;
      return 1;
    }

    auto client = authResult.getGhostFs();

    // Open local file for writing
    int fd = ::open(local_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
      std::cerr << "Error: Cannot create local file: " << local_path << " (" << strerror(errno)
                << ")" << std::endl;
      return 1;
    }

    int64_t offset = 0;
    int64_t total_downloaded = 0;

    while (true) {
      auto request = client.bulkReadRequest();
      auto req = request.initReq();
      req.setPath(remote_path);
      req.setOffset(offset);
      req.setSize(CHUNK_SIZE);

      auto readPromise = request.send();
      auto readTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                             .then([]() -> capnp::Response<GhostFS::BulkReadResults> {
                               KJ_FAIL_REQUIRE("Download timed out");
                             });
      auto result = readPromise.exclusiveJoin(kj::mv(readTimeout)).wait(ioContext.waitScope);

      auto res = result.getRes();
      if (res.getRes() == -1) {
        if (offset == 0) {
          std::cerr << "Error: Cannot read remote file: " << remote_path << " (errno "
                    << static_cast<int>(res.getErrno()) << ")" << std::endl;
          ::close(fd);
          return 1;
        }
        break;  // EOF or error after reading some data
      }

      auto data = res.getBuf();
      if (data.size() == 0) {
        break;  // EOF
      }

      ssize_t written = ::write(fd, data.begin(), data.size());
      if (written != static_cast<ssize_t>(data.size())) {
        std::cerr << "Error writing local file: " << strerror(errno) << std::endl;
        ::close(fd);
        return 1;
      }
      total_downloaded += written;

      offset += data.size();

      if (config.show_progress) {
        std::cout << "\rDownloaded " << total_downloaded << " bytes..." << std::flush;
      }
    }

    ::close(fd);

    if (config.show_progress) {
      std::cout << std::endl;
    }
    std::cout << "Downloaded " << total_downloaded << " bytes to " << local_path << std::endl;

    return 0;
  }

  // Server-side copy (GhostFS to GhostFS)
  static int copy_server_side(const CopyConfig& config) {
    std::string src_path = strip_gfs_prefix(config.source);
    std::string dst_path = strip_gfs_prefix(config.destination);

    // Remove leading slashes if present
    if (!src_path.empty() && src_path[0] == '/') {
      src_path = src_path.substr(1);
    }
    if (!dst_path.empty() && dst_path[0] == '/') {
      dst_path = dst_path.substr(1);
    }

    // Setup RPC connection
    auto ioContext = kj::setupAsyncIo();
    auto& timer = ioContext.provider->getTimer();

    kj::Own<kj::AsyncIoStream> connection;

    // DNS resolution with timeout
    auto addressPromise = ioContext.provider->getNetwork().parseAddress(config.host, config.port);
    auto addressTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::NetworkAddress> {
                                KJ_FAIL_REQUIRE("DNS resolution timed out");
                              });
    auto address = addressPromise.exclusiveJoin(kj::mv(addressTimeout)).wait(ioContext.waitScope);

    // TCP connection with timeout
    auto connectPromise = address->connect();
    auto connectTimeout = timer.afterDelay(CONNECTION_TIMEOUT_MS * kj::MILLISECONDS)
                              .then([]() -> kj::Own<kj::AsyncIoStream> {
                                KJ_FAIL_REQUIRE("Connection timed out");
                              });
    connection = connectPromise.exclusiveJoin(kj::mv(connectTimeout)).wait(ioContext.waitScope);

    capnp::TwoPartyClient twoParty(*connection);
    auto rpcCapability = twoParty.bootstrap();
    auto authClient = rpcCapability.castAs<GhostFSAuth>();

    auto authRequest = authClient.authRequest();
    authRequest.setUser(config.user);
    authRequest.setToken(config.token);

    // Auth RPC with timeout
    auto authPromise = authRequest.send();
    auto authTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                           .then([]() -> capnp::Response<GhostFSAuth::AuthResults> {
                             KJ_FAIL_REQUIRE("Authentication timed out");
                           });
    auto authResult = authPromise.exclusiveJoin(kj::mv(authTimeout)).wait(ioContext.waitScope);

    if (!authResult.getAuthSuccess()) {
      std::cerr << "Error: Authentication failed" << std::endl;
      return 1;
    }

    auto client = authResult.getGhostFs();

    // Make server-side copy request
    auto request = client.copyFileRequest();
    auto req = request.initReq();
    req.setSrcPath(src_path);
    req.setDstPath(dst_path);

    auto copyPromise = request.send();
    auto copyTimeout = timer.afterDelay(RPC_TIMEOUT_MS * kj::MILLISECONDS)
                           .then([]() -> capnp::Response<GhostFS::CopyFileResults> {
                             KJ_FAIL_REQUIRE("Copy timed out");
                           });
    auto result = copyPromise.exclusiveJoin(kj::mv(copyTimeout)).wait(ioContext.waitScope);

    auto res = result.getRes();
    if (res.getRes() != 0) {
      std::cerr << "Error: Server-side copy failed with errno " << static_cast<int>(res.getErrno())
                << std::endl;
      return 1;
    }

    std::cout << "Copied " << res.getBytesCopied() << " bytes from " << config.source << " to "
              << config.destination << " (server-side)" << std::endl;

    return 0;
  }

  int run_copy(const CopyConfig& config) {
    // Validate paths
    if (config.source.empty() || config.destination.empty()) {
      std::cerr << "Error: Source and destination paths are required" << std::endl;
      return 1;
    }

    bool src_is_gfs = is_gfs_path(config.source);
    bool dst_is_gfs = is_gfs_path(config.destination);

    // At least one path must be a GhostFS path
    if (!src_is_gfs && !dst_is_gfs) {
      std::cerr << "Error: At least one path must be a GhostFS path (gfs:/path)" << std::endl;
      return 1;
    }

    // Validate GhostFS connection parameters if needed
    if ((src_is_gfs || dst_is_gfs)
        && (config.host.empty() || config.user.empty() || config.token.empty())) {
      std::cerr << "Error: --host, --user, and --token are required for GhostFS paths" << std::endl;
      return 1;
    }

    // Handle encryption
    if (config.encrypt) {
      if (config.encryption_key.empty()) {
        std::cerr << "Error: --encrypt requires --encryption-key" << std::endl;
        return 1;
      }
      if (!crypto::init()) {
        std::cerr << "Error: Failed to initialize encryption" << std::endl;
        return 1;
      }
      if (!crypto::load_key_file(config.encryption_key, g_copy_encryption_key)) {
        std::cerr << "Error: Failed to load encryption key: " << config.encryption_key << std::endl;
        return 1;
      }
      g_copy_encryption_enabled = true;
    }

    // Determine copy type and execute
    if (src_is_gfs && dst_is_gfs) {
      // Server-side copy
      return copy_server_side(config);
    } else if (src_is_gfs) {
      // Download: GhostFS -> local
      return copy_download(config);
    } else {
      // Upload: local -> GhostFS
      return copy_upload(config);
    }
  }

}  // namespace ghostfs
