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

struct cached_write {
  fuse_req_t req;
  fuse_ino_t ino;
  char *buf;
  size_t size;
  off_t off;
  struct fuse_file_info *fi;
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

  void init() {
    if (initialized) return;

    ioContext = std::make_unique<kj::AsyncIoContext>(kj::setupAsyncIo());

    if (g_conn_params.cert.length()) {
      kj::TlsContext::Options options;
      kj::TlsCertificate caCert(g_conn_params.cert);
      options.trustedCertificates = kj::arrayPtr(&caCert, 1);

      kj::TlsContext tls(kj::mv(options));
      auto network = tls.wrapNetwork(ioContext->provider->getNetwork());
      auto address = network->parseAddress(g_conn_params.host, g_conn_params.port)
                         .wait(ioContext->waitScope);
      connection = address->connect().wait(ioContext->waitScope);
    } else {
      auto address = ioContext->provider->getNetwork()
                         .parseAddress(g_conn_params.host, g_conn_params.port)
                         .wait(ioContext->waitScope);
      connection = address->connect().wait(ioContext->waitScope);
    }

    twoParty = std::make_unique<capnp::TwoPartyClient>(*connection);
    auto rpcCapability = twoParty->bootstrap();
    auto authClient = rpcCapability.castAs<GhostFSAuth>();
    auto request = authClient.authRequest();
    request.setUser(g_conn_params.user);
    request.setToken(g_conn_params.token);
    auto result = request.send().wait(ioContext->waitScope);

    if (!result.getAuthSuccess()) {
      throw std::runtime_error("Thread-local authentication failed");
    }

    client = result.getGhostFs();
    initialized = true;
  }
};

thread_local ThreadLocalRpc tl_rpc;

// Helper to get thread-local RPC client
inline ThreadLocalRpc& getRpc() {
  tl_rpc.init();
  return tl_rpc;
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
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->getattrRequest();

  Getattr::Builder getattr = request.getReq();
  Getattr::FuseFileInfo::Builder fuseFileInfo = getattr.initFi();

  getattr.setIno(ino);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "ghostfs_ll_getattr executed correctly: " << payload << std::endl;
}

/**
 * @brief
 *
 * @param req
 * @param parent -> uint64_t
 * @param name -> *char
 */
static void ghostfs_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->lookupRequest();

  Lookup::Builder lookup = request.getReq();

  lookup.setParent(parent);
  lookup.setName(name);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "ghostfs_ll_lookup executed correctly" << std::endl;
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
  // printf("Called .readdir\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->readdirRequest();

  Readdir::Builder readdir = request.getReq();
  Readdir::FuseFileInfo::Builder fuseFileInfo = readdir.initFi();

  readdir.setIno(ino);
  readdir.setSize(size);
  readdir.setOff(off);

  fillFileInfo(&fuseFileInfo, fi);

  // Don't remove these 3 lines
  // const auto m = capnp::messageToFlatArray(message);
  // const auto c = m.asChars();
  // std::cout << "Size: " << c.size() << std::endl;

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  struct dirbuf b;

  memset(&b, 0, sizeof(b));

  int res = response.getRes();

  if (res == -1) {
    // std::cout << "READDIR::ENOENT" << std::endl;
    fuse_reply_err(req, response.getErrno());
    return;
  }

  for (ReaddirResponse::Entry::Reader entry : response.getEntries()) {
    dirbuf_add(req, &b, entry.getName().cStr(), entry.getIno());
  }

  reply_buf_limited(req, b.p, b.size, off, size);
  // free(b.p);

  // std::cout << "ghostfs_ll_readdir executed correctly: " << payload << std::endl;
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
  // printf("Called .open\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->openRequest();

  Open::Builder open = request.getReq();
  Open::FuseFileInfo::Builder fuseFileInfo = open.initFi();

  open.setIno(ino);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    int err = response.getErrno();
    fuse_reply_err(req, err);
    return;
  }

  OpenResponse::FuseFileInfo::Reader fi_response = response.getFi();

  // fi.cache_readdir = fi_response.getCacheReaddir();
  // fi.direct_io = fi_response.getDirectIo();
  fi->fh = fi_response.getFh();
  // fi.flags = fi_response.getFlags();
  //  fi.flush = fi_response.getFlush();
  // fi.keep_cache = fi_response.getKeepCache();
  // fi.lock_owner = fi_response.getLockOwner();
  //  fi.noflush = fi_response.getNoflush();
  // fi.nonseekable = fi_response.getNonseekable();
  // fi.padding = fi_response.getPadding();
  //  fi.poll_events = fi_response.getPollEvents();
  // fi.writepage = fi_response.getWritepage();

  fuse_reply_open(req, fi);

  // std::cout << "ghostfs_ll_open executed correctly: " << payload << std::endl;
}

bool reply_from_cache(fuse_req_t req, uint64_t fh, size_t size, off_t off) {
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
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->readRequest();

  Read::Builder read = request.getReq();
  Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

  read.setIno(ino);
  read.setSize(size * max_read_ahead_cache);
  read.setOff(off);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    // std::cout << "READ::ENOENT" << std::endl;
    fuse_reply_err(req, response.getErrno());
    return;
  }

  capnp::Data::Reader buf_reader = response.getBuf();
  const auto chars = buf_reader.asChars();
  const char *buf = chars.begin();

  // reply_buf_limited(request.req, buf, chars.size(), request.off, request.size);

  fuse_reply_buf(req, buf, min(size, static_cast<size_t>(res)));

  if (static_cast<size_t>(res) > size) {
    if (read_ahead_cache.contains(fi->fh)) {
      free(read_ahead_cache[fi->fh].buf);
    }

    cached_read cache = {ino, (char *)malloc(res), static_cast<size_t>(res), off, fi};
    memcpy(cache.buf, buf, res);
    read_ahead_cache[fi->fh] = cache;
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
  // printf("Called .read\n");

  if (max_read_ahead_cache > 0) {
    bool is_cached = reply_from_cache(req, fi->fh, size, off);

    if (!is_cached) {
      read_ahead(req, ino, size, off, fi);
    }

    return;
  }

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->readRequest();

  Read::Builder read = request.getReq();
  Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

  read.setIno(ino);
  read.setSize(size);
  read.setOff(off);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    // std::cout << "READ::ENOENT" << std::endl;
    fuse_reply_err(req, response.getErrno());
    return;
  }

  capnp::Data::Reader buf_reader = response.getBuf();
  const auto chars = buf_reader.asChars();
  const char *buf = chars.begin();

  // reply_buf_limited(request.req, buf, chars.size(), request.off, request.size);

  fuse_reply_buf(req, buf, res);

  // std::cout << "ghostfs_ll_read executed correctly: " << payload << std::endl;
}

uint64_t add_to_write_back_cache(cached_write cache) {
  if (not write_back_cache.contains(cache.fi->fh)) {
    write_back_cache[cache.fi->fh] = std::vector<cached_write>();
  }

  write_back_cache[cache.fi->fh].push_back(cache);
  return write_back_cache[cache.fi->fh].size();
}

void flush_write_back_cache(uint64_t fh, bool reply) {
  if (not write_back_cache.contains(fh)) {
    return;
  }

  uint64_t cached = write_back_cache[fh].size();

  if (cached == 0) {
    return;
  }

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->bulkWriteRequest();

  capnp::List<Write>::Builder write = request.initReq(cached);

  uint8_t i = 0;
  for (auto cache : write_back_cache[fh]) {
    write[i].setIno(cache.ino);
    write[i].setOff(cache.off);
    write[i].setSize(cache.size);

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte *)cache.buf, cache.size);
    capnp::Data::Reader buf_reader(buf_ptr);
    write[i].setBuf(buf_reader);

    Write::FuseFileInfo::Builder fuseFileInfo = write[i].initFi();
    fillFileInfo(&fuseFileInfo, cache.fi);

    i++;
  }

  auto promise = request.send();
  auto result = promise.wait(waitScope);

  if (reply) {
    auto response = result.getRes();
    int res = response[cached - 1].getRes();
    auto req = write_back_cache[fh][cached - 1].req;

    if (res == -1) {
      fuse_reply_err(req, response[cached - 1].getErrno());
    } else {
      fuse_reply_write(req, response[cached - 1].getWritten());
    }
  }

  for (auto cache : write_back_cache[fh]) {
    free(cache.buf);
  }

  write_back_cache[fh].clear();
  write_back_cache.erase(fh);
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
  // printf("Called .write\n");

  if (max_read_ahead_cache > 0) {
    read_ahead_cache.erase(fi->fh);
  }

  if (max_write_back_cache > 0) {
    cached_write cache = {req, ino, (char *)malloc(size), size, off, fi};
    memcpy(cache.buf, buf, size);
    uint64_t cached = add_to_write_back_cache(cache);

    if (cached >= max_write_back_cache) {
      flush_write_back_cache(fi->fh, true);
    } else {
      fuse_reply_write(req, size);
    }

    return;
  }

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
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

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    // std::cout << "WRITE::ENOENT" << std::endl;
    fuse_reply_err(req, response.getErrno());
    return;
  }

  fuse_reply_write(req, response.getWritten());

  // std::cout << "ghostfs_ll_write executed correctly: " << payload << std::endl;
}

static void ghostfs_ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  // printf("Called .unlink\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->unlinkRequest();

  Unlink::Builder unlink = request.getReq();

  unlink.setParent(parent);
  unlink.setName(name);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);

  // std::cout << "unlink executed correctly: " << payload << std::endl;
}

static void ghostfs_ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  // printf("Called .rmdir\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->rmdirRequest();

  Rmdir::Builder rmdir = request.getReq();

  rmdir.setParent(parent);
  rmdir.setName(name);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);

  // std::cout << "rmdir executed correctly: " << payload << std::endl;
}

static void ghostfs_ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                               const char *name) {
  // printf("Called .symlink\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->symlinkRequest();

  Symlink::Builder symlink = request.getReq();

  symlink.setLink(link);
  symlink.setParent(parent);
  symlink.setName(name);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "symlink executed correctly: " << payload << std::endl;
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
  // printf("Called .mknod\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->mknodRequest();

  Mknod::Builder mknod = request.getReq();

  mknod.setParent(parent);
  mknod.setName(name);
  mknod.setMode(mode);
  mknod.setRdev(rdev);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "ghostfs_ll_mknod executed correctly: " << payload << std::endl;
}

/**
 * @brief
 *
 * @param req
 * @param ino -> uint64_t
 * @param mask -> int
 */
static void ghostfs_ll_access(fuse_req_t req, fuse_ino_t ino, int mask) {
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->accessRequest();

  Access::Builder access = request.getReq();

  access.setIno(ino);
  access.setMask(mask);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    fuse_reply_err(req, response.getErrno());
  } else {
    fuse_reply_err(req, 0);
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
  // printf("Called .create\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->createRequest();

  Create::Builder create = request.getReq();
  Create::FuseFileInfo::Builder fuseFileInfo = create.initFi();

  create.setParent(parent);
  create.setName(name);
  create.setMode(mode);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "ghostfs_ll_create executed correctly: " << payload << std::endl;
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
  // printf("Called .mkdir\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->mkdirRequest();

  Mkdir::Builder mkdir = request.getReq();

  mkdir.setParent(parent);
  mkdir.setName(name);
  mkdir.setMode(mode);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
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

  // std::cout << "ghostfs_ll_mkdir executed correctly: " << payload << std::endl;
}

static void ghostfs_ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                              fuse_ino_t newparent, const char *newname) {
  // printf("Called .rename\n");

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->renameRequest();

  Rename::Builder rename = request.getReq();

  rename.setParent(parent);
  rename.setName(name);
  rename.setNewparent(newparent);
  rename.setNewname(newname);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);

  // std::cout << "ghostfs_ll_rename executed correctly: " << payload << std::endl;
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
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->releaseRequest();

  Release::Builder release = request.getReq();
  Release::FuseFileInfo::Builder fuseFileInfo = release.initFi();

  release.setIno(ino);
  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);

  // std::cout << "ghostfs_ll_release executed correctly: " << payload << std::endl;
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

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->flushRequest();

  Flush::Builder flush = request.getReq();
  Flush::FuseFileInfo::Builder fuseFileInfo = flush.initFi();

  flush.setIno(ino);
  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);
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

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->fsyncRequest();

  Fsync::Builder fsync = request.getReq();
  Fsync::FuseFileInfo::Builder fuseFileInfo = fsync.initFi();

  fsync.setIno(ino);
  fsync.setDatasync(datasync);

  fillFileInfo(&fuseFileInfo, fi);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();
  int err = response.getErrno();

  fuse_reply_err(req, res == -1 ? err : 0);
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
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
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

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    fuse_reply_err(req, response.getErrno());
    return;
  }

  ghostfs_ll_getattr(req, response.getIno(), fi);

  // std::cout << "ghostfs_ll_setattr executed correctly: " << payload << std::endl;
}

#ifdef __APPLE__
static void ghostfs_ll_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value,
                              size_t size, int flags, uint32_t position) {

  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->setxattrRequest();

  Setxattr::Builder setxattr = request.getReq();

  setxattr.setIno(ino);
  setxattr.setName(name);
  setxattr.setValue(value);
  setxattr.setSize(size);
  setxattr.setFlags(flags);
  setxattr.setPosition(position);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    fuse_reply_err(req, response.getErrno());
    return;
  }

  // std::cout << "ghostfs_ll_setxattr executed correctly: " << payload << std::endl;
}
#endif

static void ghostfs_ll_readlink(fuse_req_t req, fuse_ino_t ino) {
  auto &rpc = getRpc();
  auto &waitScope = rpc.ioContext->waitScope;
  auto request = rpc.client->readlinkRequest();

  Readlink::Builder readlink = request.getReq();

  readlink.setIno(ino);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto response = result.getRes();

  int res = response.getRes();

  if (res == -1) {
    int err = response.getErrno();
    fuse_reply_err(req, err);
  } else {
    std::string link = response.getLink();
    fuse_reply_readlink(req, link.c_str());
  }
}

// clang-format off
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

  // Disable caching in multi-threaded mode to avoid race conditions.
  // Multi-threaded FUSE is required to handle symlink re-entry when symlinks
  // point back to the same mount, but caching with shared state across threads
  // would require complex synchronization. The performance impact is acceptable
  // as RPC calls are already the bottleneck.
  max_write_back_cache = 0;
  max_read_ahead_cache = 0;
  (void)write_back_cache_size;  // Unused in multi-threaded mode
  (void)read_ahead_cache_size;  // Unused in multi-threaded mode

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
  } catch (const std::exception& e) {
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
      fuse_remove_signal_handlers(se);
      fuse_session_remove_chan(ch);
    }
    fuse_session_destroy(se);
  }

  fuse_unmount(mountpoint, ch);
  fuse_opt_free_args(&args);
  free_capnp_resources();

  return err ? 1 : 0;
}
