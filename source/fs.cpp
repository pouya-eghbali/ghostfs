#define FUSE_USE_VERSION 29

#include <assert.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
#include <ghostfs/fs.h>
#include <ghostfs/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <vector>

// Cap'n'Proto
#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/serialize-packed.h>
#include <kj/async-io.h>
#include <kj/async.h>
#include <kj/compat/tls.h>
#include <kj/threadlocal.h>

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

uint8_t max_write_back_cache = 8;
uint8_t max_read_ahead_cache = 8;

// Maximum read-ahead buffer size to prevent memory explosion (16MB)
constexpr size_t MAX_READ_AHEAD_BYTES = 16 * 1024 * 1024;

struct cached_write {
  fuse_req_t req;
  fuse_ino_t ino;
  char *buf;
  size_t size;
  off_t off;
  struct fuse_file_info fi;  // Store copy, not pointer (stack memory invalid after write returns)
};

struct cached_read {
  fuse_ino_t ino;
  char *buf;
  size_t size;
  off_t off;
  struct fuse_file_info *fi;
};

std::map<uint64_t, std::vector<cached_write>> write_back_cache;
std::map<uint64_t, cached_read> read_ahead_cache;

// Mutexes for thread-safe cache access
std::mutex write_cache_mutex;
std::mutex read_cache_mutex;

std::map<uint64_t, std::string> ino_to_path;
std::map<std::string, uint64_t> path_to_ino;

uint64_t current_ino = 1;

// Global connection parameters for thread-local client creation
struct ConnectionParams {
  std::string host;
  int port;
  std::string user;
  std::string token;
  std::string cert;
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

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off,
                             size_t maxsize) {
  if (off < (int64_t)bufsize) {
    return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));

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
  uint64_t parent_ino = path_to_ino[parent_path];

  return parent_ino;
}

template <class T> void fillFileInfo(T *fuseFileInfo, struct fuse_file_info *fi) {
  if (!fi) return;

  fuseFileInfo->setFlags(fi->flags);
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

  if (not ino_to_path.contains(ino)) {
    // File is unknown
    return -1;
  }

  int res = lstat(ino_to_path[ino].c_str(), stbuf);
  stbuf->st_ino = ino;

  return res;
}

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

    fuse_reply_attr(req, &attr, 1.0);
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
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

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

    fuse_reply_entry(req, &e);
  } catch (const kj::Exception &e) {
    std::cerr << "lookup error: " << e.getDescription().cStr() << std::endl;
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

    struct dirbuf b;

    memset(&b, 0, sizeof(b));

    int res = response.getRes();

    if (res == -1) {
      fuse_reply_err(req, response.getErrno());
      return;
    }

    for (ReaddirResponse::Entry::Reader entry : response.getEntries()) {
      dirbuf_add(req, &b, entry.getName().cStr(), entry.getIno());
    }

    reply_buf_limited(req, b.p, b.size, off, size);
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
    auto request = rpc.client->openRequest();

    Open::Builder open = request.getReq();
    Open::FuseFileInfo::Builder fuseFileInfo = open.initFi();

    open.setIno(ino);

    fillFileInfo(&fuseFileInfo, fi);

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

    fuse_reply_open(req, fi);
  } catch (const kj::Exception &e) {
    std::cerr << "open error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

bool reply_from_cache(fuse_req_t req, uint64_t fh, size_t size, off_t off) {
  std::lock_guard<std::mutex> lock(read_cache_mutex);

  if (not read_ahead_cache.contains(fh)) {
    return false;
  }

  cached_read cache = read_ahead_cache[fh];

  if (cache.off > off) {
    return false;
  }

  uint64_t cache_end = cache.off + cache.size;
  uint64_t read_end = off + size;

  if (read_end > cache_end) {
    return false;
  }

  fuse_reply_buf(req, cache.buf + (off - cache.off), size);
  return true;
}

void read_ahead(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->readRequest();

    Read::Builder read = request.getReq();
    Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

    // Cap the read-ahead size to prevent memory explosion
    size_t read_ahead_size = size * max_read_ahead_cache;
    if (read_ahead_size > MAX_READ_AHEAD_BYTES) {
      read_ahead_size = MAX_READ_AHEAD_BYTES;
    }

    read.setIno(ino);
    read.setSize(read_ahead_size);
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
    const char *buf = chars.begin();

    fuse_reply_buf(req, buf, min(size, static_cast<size_t>(res)));

    if (static_cast<size_t>(res) > size) {
      std::lock_guard<std::mutex> lock(read_cache_mutex);

      if (read_ahead_cache.contains(fi->fh)) {
        free(read_ahead_cache[fi->fh].buf);
      }

      cached_read cache = {ino, (char *)malloc(res), static_cast<size_t>(res), off, fi};
      memcpy(cache.buf, buf, res);
      read_ahead_cache[fi->fh] = cache;
    }
  } catch (const kj::Exception &e) {
    std::cerr << "read_ahead error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
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
  if (max_read_ahead_cache > 0) {
    bool is_cached = reply_from_cache(req, fi->fh, size, off);

    if (!is_cached) {
      read_ahead(req, ino, size, off, fi);
    }

    return;
  }

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
    const char *buf = chars.begin();

    fuse_reply_buf(req, buf, res);
  } catch (const kj::Exception &e) {
    std::cerr << "read error: " << e.getDescription().cStr() << std::endl;
    fuse_reply_err(req, ETIMEDOUT);
  }
}

uint64_t add_to_write_back_cache(cached_write cache) {
  std::lock_guard<std::mutex> lock(write_cache_mutex);

  if (not write_back_cache.contains(cache.fi.fh)) {
    write_back_cache[cache.fi.fh] = std::vector<cached_write>();
  }

  write_back_cache[cache.fi.fh].push_back(cache);
  return write_back_cache[cache.fi.fh].size();
}

void flush_write_back_cache(uint64_t fh, bool reply) {
  std::vector<cached_write> entries_to_flush;

  // Extract entries under lock, then release lock before RPC
  {
    std::lock_guard<std::mutex> lock(write_cache_mutex);

    if (not write_back_cache.contains(fh)) {
      return;
    }

    if (write_back_cache[fh].empty()) {
      return;
    }

    entries_to_flush = std::move(write_back_cache[fh]);
    write_back_cache.erase(fh);
  }

  uint64_t cached = entries_to_flush.size();

  try {
    auto &rpc = getRpc();
    auto &waitScope = rpc.ioContext->waitScope;
    auto &timer = rpc.getTimer();
    auto request = rpc.client->bulkWriteRequest();

    capnp::List<Write>::Builder write = request.initReq(cached);

    uint8_t i = 0;
    for (auto &cache : entries_to_flush) {
      write[i].setIno(cache.ino);
      write[i].setOff(cache.off);
      write[i].setSize(cache.size);

      kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte *)cache.buf, cache.size);
      capnp::Data::Reader buf_reader(buf_ptr);
      write[i].setBuf(buf_reader);

      Write::FuseFileInfo::Builder fuseFileInfo = write[i].initFi();
      fillFileInfo(&fuseFileInfo, &cache.fi);

      i++;
    }

    auto result = waitWithTimeout(request.send(), timer, waitScope);

    if (reply) {
      auto response = result.getRes();
      int res = response[cached - 1].getRes();
      auto req = entries_to_flush[cached - 1].req;

      if (res == -1) {
        fuse_reply_err(req, response[cached - 1].getErrno());
      } else {
        fuse_reply_write(req, response[cached - 1].getWritten());
      }
    }
  } catch (const kj::Exception &e) {
    std::cerr << "flush_write_back_cache error: " << e.getDescription().cStr() << std::endl;
    if (reply && cached > 0) {
      fuse_reply_err(entries_to_flush[cached - 1].req, ETIMEDOUT);
    }
  }

  for (auto &cache : entries_to_flush) {
    free(cache.buf);
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
  if (max_read_ahead_cache > 0) {
    std::lock_guard<std::mutex> lock(read_cache_mutex);
    if (read_ahead_cache.contains(fi->fh)) {
      free(read_ahead_cache[fi->fh].buf);
      read_ahead_cache.erase(fi->fh);
    }
  }

  if (max_write_back_cache > 0) {
    cached_write cache = {req, ino, (char *)malloc(size), size, off, *fi};  // Copy fi, not pointer
    memcpy(cache.buf, buf, size);
    uint64_t cached = add_to_write_back_cache(cache);

    if (cached >= max_write_back_cache) {
      flush_write_back_cache(fi->fh, true);
    } else {
      fuse_reply_write(req, size);
    }

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
      e.attr_timeout = 1.0;
      e.entry_timeout = 1.0;

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
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

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

    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));
    e.ino = response.getIno();
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

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

    fuse_reply_create(req, &e, fi);
  } catch (const kj::Exception &e) {
    std::cerr << "create error: " << e.getDescription().cStr() << std::endl;
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
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

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
  flush_write_back_cache(fi->fh, false);

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
  flush_write_back_cache(fi->fh, false);

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
  flush_write_back_cache(fi->fh, false);

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
    attributes.setStSize(attr->st_size);
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

// clang-format off
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static const struct fuse_lowlevel_ops ghostfs_ll_oper = {
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
             uint8_t read_ahead_cache_size, std::string cert_file) {
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
