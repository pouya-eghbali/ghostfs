#include <errno.h>
#include <fcntl.h>
#include <fmt/format.h>
#include <fuse_lowlevel.h>
#include <ghostfs/auth.h>
#include <ghostfs/fs.h>
#include <ghostfs/rpc.h>
#include <limits.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifdef __APPLE__
#  include <copyfile.h>
#endif

#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <thread>

// Cap'n'Proto
#include <access.capnp.h>
#include <access.response.capnp.h>
#include <capnp/ez-rpc.h>
#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/serialize-packed.h>
#include <kj/async-io.h>
#include <kj/async.h>
#include <kj/compat/tls.h>
#include <kj/debug.h>

// Cap'n'Proto methods
#include <bulkread.capnp.h>
#include <bulkread.response.capnp.h>
#include <bulkupload.capnp.h>
#include <bulkupload.response.capnp.h>
#include <copyfile.capnp.h>
#include <copyfile.response.capnp.h>
#include <create.capnp.h>
#include <create.response.capnp.h>
#include <flush.capnp.h>
#include <flush.response.capnp.h>
#include <fsync.capnp.h>
#include <fsync.response.capnp.h>
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
#include <unlink.capnp.h>
#include <unlink.response.capnp.h>
#include <write.capnp.h>
#include <write.response.capnp.h>
#include <openandread.capnp.h>
#include <openandread.response.capnp.h>

#include <filesystem>
#include <list>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

// Global file handle sets per user (shared across all connections for same user)
// This allows multi-threaded FUSE clients to share file handles across connections
std::unordered_map<std::string, std::set<int64_t>> user_fh_sets;
std::shared_mutex g_fh_mutex;  // Protects user_fh_sets

// ============== SERVER-SIDE READ-AHEAD CACHE ==============
// Cache recently read data on the server to reduce pread() syscalls
// Similar to how MinIO caches data in memory
struct ServerReadCache {
  static constexpr size_t CACHE_SIZE = 8 * 1024 * 1024;   // 8MB per file handle
  static constexpr size_t PREFETCH_MULTIPLIER = 2;        // Read 2x what's requested

  std::vector<char> buffer;
  off_t start_off{0};
  size_t valid_size{0};
  int64_t fh{-1};

  ServerReadCache() : buffer(CACHE_SIZE) {}

  bool contains(off_t off, size_t size) const {
    if (fh < 0 || valid_size == 0) return false;
    return off >= start_off && (off + static_cast<off_t>(size)) <= (start_off + static_cast<off_t>(valid_size));
  }

  const char* get_data(off_t off) const {
    return buffer.data() + (off - start_off);
  }

  // Fill cache starting at offset, reading up to CACHE_SIZE bytes
  ssize_t fill(int64_t file_handle, off_t off) {
    fh = file_handle;
    start_off = off;

    ssize_t res = ::pread(fh, buffer.data(), CACHE_SIZE, off);
    valid_size = res > 0 ? static_cast<size_t>(res) : 0;
    return res;
  }
};

// Per-file-handle cache (LRU with max entries)
static constexpr size_t MAX_SERVER_CACHE_ENTRIES = 16;
std::unordered_map<int64_t, std::unique_ptr<ServerReadCache>> g_server_read_cache;
std::list<int64_t> g_server_cache_lru;  // Front = most recently used
std::mutex g_server_cache_mutex;

ServerReadCache* get_server_cache(int64_t fh) {
  std::lock_guard<std::mutex> lock(g_server_cache_mutex);

  auto it = g_server_read_cache.find(fh);
  if (it != g_server_read_cache.end()) {
    // Move to front of LRU
    g_server_cache_lru.remove(fh);
    g_server_cache_lru.push_front(fh);
    return it->second.get();
  }

  // Create new cache entry
  // Evict oldest if at capacity
  while (g_server_read_cache.size() >= MAX_SERVER_CACHE_ENTRIES && !g_server_cache_lru.empty()) {
    int64_t oldest = g_server_cache_lru.back();
    g_server_cache_lru.pop_back();
    g_server_read_cache.erase(oldest);
  }

  auto& cache = g_server_read_cache[fh];
  cache = std::make_unique<ServerReadCache>();
  g_server_cache_lru.push_front(fh);
  return cache.get();
}

void remove_server_cache(int64_t fh) {
  std::lock_guard<std::mutex> lock(g_server_cache_mutex);
  g_server_read_cache.erase(fh);
  g_server_cache_lru.remove(fh);
}
// ============== END SERVER-SIDE READ-AHEAD CACHE ==============

class GhostFSImpl final : public GhostFS::Server {
  std::string user;
  std::string root;
  std::string suffix;

  std::string get_path_from_ino(uint64_t ino) {
    // ROOT
    if (ino == 1) {
      return normalize_path(root, user, suffix);
    }
    return get_path_for_ino(ino);
  }

public:
  explicit GhostFSImpl(std::string _user, std::string _root, std::string _suffix)
      : user(std::move(_user)), root(std::move(_root)), suffix(std::move(_suffix)) {}

  kj::Promise<void> lookup(LookupContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();
    std::string name = req.getName();

    std::map<std::string, std::string>* mounts = get_user_mounts(user);
    bool is_mount = parent == 1 && mounts->contains(name);
    std::filesystem::path file_path;

    if (is_mount) {
      file_path = std::filesystem::path(root) / (*mounts)[name];
    } else {
      std::string user_root = normalize_path(root, user, suffix);
      std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
      std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
      file_path = parent_path / std::filesystem::path(name);
    }

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    uint64_t ino = assign_inode(file_path.string());

    response.setIno(ino);

    // e.attr_timeout = 1.0;
    // e.entry_timeout = 1.0;

    struct stat attr;

    memset(&attr, 0, sizeof(attr));

    int res = ghostfs_stat(ino, &attr);
    int err = errno;

    LookupResponse::Attr::Builder attributes = response.initAttr();

    attributes.setStDev(attr.st_dev);
    attributes.setStIno(attr.st_ino);
    attributes.setStMode(attr.st_mode);
    attributes.setStNlink(attr.st_nlink);
    attributes.setStUid(attr.st_uid);
    attributes.setStGid(attr.st_gid);
    attributes.setStRdev(attr.st_rdev);
    attributes.setStSize(attr.st_size);
    attributes.setStAtime(attr.st_atime);
    attributes.setStMtime(attr.st_mtime);
    attributes.setStCtime(attr.st_ctime);
    attributes.setStBlksize(attr.st_blksize);
    attributes.setStBlocks(attr.st_blocks);

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> getattr(GetattrContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    struct stat attr;

    memset(&attr, 0, sizeof(attr));

    int64_t fh = req.getFi().getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    int res = ghostfs_stat(req.getIno(), fh, &attr);
    int err = errno;

    GetattrResponse::Attr::Builder attributes = response.initAttr();

    attributes.setStDev(attr.st_dev);
    attributes.setStIno(attr.st_ino);
    attributes.setStMode(attr.st_mode);
    attributes.setStNlink(attr.st_nlink);
    attributes.setStUid(attr.st_uid);
    attributes.setStGid(attr.st_gid);
    attributes.setStRdev(attr.st_rdev);
    attributes.setStSize(attr.st_size);
    attributes.setStAtime(attr.st_atime);
    attributes.setStMtime(attr.st_mtime);
    attributes.setStCtime(attr.st_ctime);
    attributes.setStBlksize(attr.st_blksize);
    attributes.setStBlocks(attr.st_blocks);

    // std::cout << "st_dev " << attr.st_dev << " " << attributes.getStDev() << std::endl;
    // std::cout << "st_ino " << attr.st_ino << " " << attributes.getStIno() << std::endl;
    // std::cout << "st_mode " << attr.st_mode << " " << attributes.getStMode() << std::endl;
    // std::cout << "st_nlink " << attr.st_nlink << " " << attributes.getStNlink() <<
    // std::endl; std::cout << "st_uid " << attr.st_uid << " " << attributes.getStUid() <<
    // std::endl; std::cout << "st_gid " << attr.st_gid << " " << attributes.getStGid() <<
    // std::endl; std::cout << "st_rdev " << attr.st_rdev << " " << attributes.getStRdev() <<
    // std::endl; std::cout << "st_size " << attr.st_size << " " << attributes.getStSize() <<
    // std::endl; std::cout << "st_atime " << attr.st_atime << " " << attributes.getStAtime()
    // << std::endl; std::cout << "st_mtime " << attr.st_mtime << " " <<
    // attributes.getStMtime() << std::endl; std::cout << "st_ctime " << attr.st_ctime << " "
    // << attributes.getStCtime() << std::endl; std::cout << "st_blksize " << attr.st_blksize
    // << " " << attributes.getStBlksize() << std::endl; std::cout << "st_blocks " <<
    // attr.st_blocks << " " << attributes.getStBlocks()
    // << std::endl;

    response.setErrno(err);
    response.setRes(res);

    // std::cout << "getattr_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }

  kj::Promise<void> setattr(SetattrContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    int err = 0;

    std::string file_path = get_path_for_ino(ino);
    if (file_path.empty()) {
      // Parent is unknown
      err = errno;
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    Setattr::Attr::Reader attr = req.getAttr();
    Setattr::Attr::TimeSpec::Reader stAtime = attr.getStAtime();
    Setattr::Attr::TimeSpec::Reader stMtime = attr.getStMtime();

    struct timespec a_time = {.tv_sec = stAtime.getTvSec(), .tv_nsec = stAtime.getTvNSec()};
    struct timespec m_time = {.tv_sec = stMtime.getTvSec(), .tv_nsec = stMtime.getTvNSec()};

    uint64_t to_set = req.getToSet();

    int res;

    if (to_set & FUSE_SET_ATTR_MODE) {
      res = chmod(file_path.c_str(), attr.getStMode());
      if (res == -1) {
        err = errno;
        response.setErrno(err);
        response.setRes(res);
        return kj::READY_NOW;
      }
    }

    if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
      uid_t uid = (to_set & FUSE_SET_ATTR_UID) ? attr.getStUid() : (uid_t)-1;
      gid_t gid = (to_set & FUSE_SET_ATTR_GID) ? attr.getStGid() : (gid_t)-1;

      res = lchown(file_path.c_str(), uid, gid);
      if (res == -1) {
        err = errno;
        response.setErrno(err);
        response.setRes(res);
        return kj::READY_NOW;
      }
    }

    if (to_set & FUSE_SET_ATTR_SIZE) {
      res = truncate(file_path.c_str(), attr.getStSize());
      if (res == -1) {
        err = errno;
        response.setErrno(err);
        response.setRes(res);
        return kj::READY_NOW;
      }
    }

    if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
      struct timespec tv[2];

      tv[0].tv_sec = 0;
      tv[1].tv_sec = 0;
      tv[0].tv_nsec = UTIME_OMIT;
      tv[1].tv_nsec = UTIME_OMIT;

      if (to_set & FUSE_SET_ATTR_ATIME_NOW) {
        tv[0].tv_nsec = UTIME_NOW;
      } else if (to_set & FUSE_SET_ATTR_ATIME) {  // clang-format off
            // #if defined(__APPLE__)
            //   tv[0] = attr->st_atimespec;
            // #else
            //   tv[0] = attr->st_atim;
            // #endif  // clang-format on
            tv[0] = a_time;
      }

      if (to_set & FUSE_SET_ATTR_MTIME_NOW) {
        tv[1].tv_nsec = UTIME_NOW;
      } else if (to_set & FUSE_SET_ATTR_MTIME) {  // clang-format off
        // #if defined(__APPLE__)
        //   tv[1] = attr->st_mtimespec;
        // #else
        //   tv[1] = attr->st_mtim;
        // #endif  // clang-format on
        tv[1] = m_time;
      }

      res = utimensat(AT_FDCWD, file_path.c_str(), tv, 0);
      err = errno;
      response.setErrno(err);


      if (res == -1) {
        response.setErrno(err);
        response.setRes(res);
        return kj::READY_NOW;
      }
    }

    response.setIno(ino);
    response.setErrno(err);
    response.setRes(0);
    return kj::READY_NOW;
  }

  kj::Promise<void> mknod(MknodContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / req.getName().cStr();

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    uint64_t file_ino = assign_inode(file_path.string());

    int fh = ::mknod(file_path.c_str(), req.getMode(), req.getRdev());
    int err = errno;

    if (fh == -1) {
      remove_inode(file_ino);
      
      response.setErrno(err);
      response.setRes(fh);
      return kj::READY_NOW;
    } else {
      {
        std::unique_lock lock(g_fh_mutex);
        user_fh_sets[user].insert(fh);
      }

      response.setIno(file_ino);

      struct stat attr;
      memset(&attr, 0, sizeof(attr));

      //e.attr_timeout = 1.0;
      //e.entry_timeout = 1.0;

      ghostfs_stat(file_ino, &attr);

      MknodResponse::Attr::Builder attributes = response.initAttr();

      attributes.setStDev(attr.st_dev);
      attributes.setStIno(attr.st_ino);
      attributes.setStMode(attr.st_mode);
      attributes.setStNlink(attr.st_nlink);
      attributes.setStUid(attr.st_uid);
      attributes.setStGid(attr.st_gid);
      attributes.setStRdev(attr.st_rdev);
      attributes.setStSize(attr.st_size);
      attributes.setStAtime(attr.st_atime);
      attributes.setStMtime(attr.st_mtime);
      attributes.setStCtime(attr.st_ctime);
      attributes.setStBlksize(attr.st_blksize);
      attributes.setStBlocks(attr.st_blocks);
    }
    
    response.setErrno(err);
    response.setRes(fh);

    // std::cout << "mknod_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }

   kj::Promise<void> mkdir(MkdirContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / req.getName().cStr();

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    int fh = ::mkdir(file_path.c_str(), req.getMode());
    int err = errno;

    if (fh == -1) {
      response.setRes(-1);
      response.setErrno(err);
      return kj::READY_NOW;
    }
    else {
      {
        std::unique_lock lock(g_fh_mutex);
        user_fh_sets[user].insert(fh);
      }

      struct stat attr;
      memset(&attr, 0, sizeof(attr));

      uint64_t file_ino = assign_inode(file_path.string());

      //e.attr_timeout = 1.0;
      //e.entry_timeout = 1.0;
      
      response.setIno(file_ino);

      ghostfs_stat(file_ino, &attr);

      MkdirResponse::Attr::Builder attributes = response.initAttr();

      attributes.setStDev(attr.st_dev);
      attributes.setStIno(attr.st_ino);
      attributes.setStMode(attr.st_mode);
      attributes.setStNlink(attr.st_nlink);
      attributes.setStUid(attr.st_uid);
      attributes.setStGid(attr.st_gid);
      attributes.setStRdev(attr.st_rdev);
      attributes.setStSize(attr.st_size);
      attributes.setStAtime(attr.st_atime);
      attributes.setStMtime(attr.st_mtime);
      attributes.setStCtime(attr.st_ctime);
      attributes.setStBlksize(attr.st_blksize);
      attributes.setStBlocks(attr.st_blocks);
    }
    
    response.setErrno(err);
    response.setRes(fh);

    // std::cout << "mkdir_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }

  kj::Promise<void> unlink(UnlinkContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();
    std::string name = req.getName();

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / std::filesystem::path(name);

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // TODO: this removes write protected files without warning
    int res = ::unlink(file_path.c_str());
    int err = errno;

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> rmdir(RmdirContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();
    std::string name = req.getName();

    // std::cout << "RMDIR name: " << name << std::endl;

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / std::filesystem::path(name);

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // std::cout << "RMDIR file_path: " << file_path.c_str() << std::endl;

    int res = ::rmdir(file_path.c_str());
    int err = errno;
    
    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> readlink(ReadlinkContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    char buf[PATH_MAX];

    std::string readlink_path = get_path_for_ino(req.getIno());
    int res = ::readlink(readlink_path.c_str(), buf, sizeof(buf) - 1);  // Decrease the buffer size by 1
    int err = errno;

    if (res >= static_cast<int>(sizeof(buf) - 1)) {
      response.setErrno(ENAMETOOLONG);
    } else {
      response.setErrno(err);
    }

    if (res != -1) {
      buf[res] = '\0';  // Null-terminate the buffer manually
    }
    
    response.setRes(res);
    
    // std::cout << "READLINK err: " << err << std::endl;
    // std::cout << "READLINK buf size: " << sizeof(buf) << std::endl;
    // std::cout << "READLINK res: " << res << std::endl;
    // std::cout << "READLINK buf: " << std::string(buf) << std::endl;

    if (res != -1) {
      response.setLink(std::string(buf, res));
    }

    return kj::READY_NOW;
  }

  kj::Promise<void> symlink(SymlinkContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    std::string link = req.getLink();
    uint64_t parent = req.getParent();
    std::string name = req.getName();

    // std::cout << "SYMLINK name: " << name << std::endl;

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / std::filesystem::path(name);

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }
    
    int fh = ::open(parent_path.c_str(), O_RDONLY|O_DIRECTORY);

    if (fh == -1) {
      int err = errno;
      response.setErrno(err);
      response.setRes(fh);
      return kj::READY_NOW;
    }

    int res = ::symlinkat(link.c_str(), fh, name.c_str());
    int err = errno;
    
    // std::cout << "symlink closing " << fh << std::endl;
    
    ::close(fh);
    
    response.setErrno(err);
    response.setRes(res);

    if (res != -1) {
      struct stat attr;
      memset(&attr, 0, sizeof(attr));

      uint64_t file_ino = assign_inode(file_path.string());

      //e.attr_timeout = 1.0;
      //e.entry_timeout = 1.0;

      response.setIno(file_ino);

      ghostfs_stat(file_ino, &attr);

      SymlinkResponse::Attr::Builder attributes = response.initAttr();

      attributes.setStDev(attr.st_dev);
      attributes.setStIno(attr.st_ino);
      attributes.setStMode(attr.st_mode);
      attributes.setStNlink(attr.st_nlink);
      attributes.setStUid(attr.st_uid);
      attributes.setStGid(attr.st_gid);
      attributes.setStRdev(attr.st_rdev);
      attributes.setStSize(attr.st_size);
      attributes.setStAtime(attr.st_atime);
      attributes.setStMtime(attr.st_mtime);
      attributes.setStCtime(attr.st_ctime);
      attributes.setStBlksize(attr.st_blksize);
      attributes.setStBlocks(attr.st_blocks);
    }

    return kj::READY_NOW;
  }

  kj::Promise<void> rename(RenameContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t parent = req.getParent();
    std::string name = req.getName();
    uint64_t newparent = req.getNewparent();
    std::string newname = req.getNewname();

    std::string user_root = normalize_path(root, user, suffix);

    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / std::filesystem::path(name);

    std::string newparent_path_name = newparent == 1 ? user_root : get_path_for_ino(newparent);
    std::filesystem::path newparent_path = std::filesystem::path(newparent_path_name);
    std::filesystem::path newfile_path = newparent_path / std::filesystem::path(newname);

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    access_ok = check_access(root, user, suffix, newfile_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // use rename
    int res = ::rename(file_path.c_str(), newfile_path.c_str());
    int err = errno;

    // fix ino to path using thread-safe update
    uint64_t ino = get_ino_for_path(file_path.string());
    if (ino != 0) {
      update_inode_path(ino, file_path.string(), newfile_path.string());
    }

    // fix ino to path recursively if we rename a directory
    // Use symlink_status to check if it's actually a directory (not a symlink to one)
    // This prevents re-entry deadlocks when symlinks point back to the FUSE mount
    auto status = std::filesystem::symlink_status(newfile_path);
    if (std::filesystem::is_directory(status)) {
      for(const auto& entry: std::filesystem::recursive_directory_iterator(newfile_path)) {
        std::filesystem::path new_name = entry.path();
        std::filesystem::path relative = std::filesystem::relative(new_name, newfile_path);
        std::filesystem::path old_name = file_path / relative;

        // Check if old_name exists before accessing to prevent auto-vivification
        uint64_t child_ino = get_ino_for_path(old_name.string());
        if (child_ino != 0) {
          update_inode_path(child_ino, old_name.string(), new_name.string());
        }
      }
    }

    response.setErrno(err);
    response.setRes(res);

    // std::cout << "rename_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }

   kj::Promise<void> open(OpenContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    std::string open_path = get_path_for_ino(req.getIno());
    if (open_path.empty()) {
      // File is unknown
      response.setRes(-1);
      response.setErrno(ENOENT);
      return kj::READY_NOW;
    }

    response.setIno(req.getIno());

    Open::FuseFileInfo::Reader fi = req.getFi();

    int64_t fh = ::open(open_path.c_str(), fi.getFlags());

    // std::cout << "open fh: " << fh << ", path: " << path << std::endl;

    int err = errno;
    response.setErrno(err);
    response.setRes(fh);

    if (fh == -1) {
      response.setRes(fh);
      return kj::READY_NOW;
    }

    {
      std::unique_lock lock(g_fh_mutex);
      user_fh_sets[user].insert(fh);
    }

    // Get file size for client prefetch decisions
    struct stat st;
    if (::fstat(fh, &st) == 0) {
      response.setSize(st.st_size);
    } else {
      response.setSize(0);  // fallback: client will use prefetch
    }

    OpenResponse::FuseFileInfo::Builder fi_response = response.initFi();

    fi_response.setCacheReaddir(fi.getCacheReaddir());
    fi_response.setDirectIo(fi.getDirectIo());
    fi_response.setFh(fh);
    fi_response.setFlags(fi.getFlags());
    fi_response.setFlush(fi.getFlush());
    fi_response.setKeepCache(fi.getKeepCache());
    fi_response.setLockOwner(fi.getLockOwner());
    fi_response.setNoflush(fi.getNoflush());
    fi_response.setNonseekable(fi.getNonseekable());
    fi_response.setPadding(fi.getPadding());
    fi_response.setPollEvents(fi.getPollEvents());
    fi_response.setWritepage(fi.getWritepage());

    // std::cout << "open_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }

  kj::Promise<void> read(ReadContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    if (!has_inode(ino)) {
      // File is unknown
      response.setRes(-1);
      response.setErrno(ENOENT);
      return kj::READY_NOW;
    }

    size_t size = req.getSize();
    off_t off = req.getOff();

    Read::FuseFileInfo::Reader fi = req.getFi();
    int64_t fh = fi.getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    ssize_t res;
    int err = 0;
    const char* data_ptr = nullptr;

    // Direct pread - no server cache (client does prefetching)
    thread_local std::vector<char> read_buffer;
    if (read_buffer.size() < size) {
      read_buffer.resize(size);
    }
    res = ::pread(fh, read_buffer.data(), size, off);
    if (res < 0) {
      err = errno;
    } else {
      data_ptr = read_buffer.data();
    }

    uint64_t bytesRead = res > 0 ? static_cast<uint64_t>(res) : 0;

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte*)data_ptr, bytesRead);
    capnp::Data::Reader buf_reader(buf_ptr);

    response.setBuf(buf_reader);
    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> write(WriteContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    Write::FuseFileInfo::Reader fi = req.getFi();
    capnp::Data::Reader buf_reader = req.getBuf();

    const auto chars = buf_reader.asChars();
    const char* buf = chars.begin();

    auto results = context.getResults();
    auto response = results.getRes();

    int64_t fh = fi.getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    ssize_t written = ::pwrite(fi.getFh(), buf, req.getSize(), req.getOff());
    int err = errno;

    //std::cout << "write err: " << err << ", written: " << written
    //          << ", fh: " << fi.getFh() << std::endl;

    response.setRes(0);
    response.setErrno(err);
    response.setIno(req.getIno());
    response.setWritten(written > 0 ? written : 0);

    // std::cout << "write_response sent correctly" << std::endl;

    return kj::READY_NOW;
  }

  kj::Promise<void> bulkWrite(BulkWriteContext context) override {
    auto params = context.getParams();
    auto reqs = params.getReq();

    int64_t count = 0;
    for ([[maybe_unused]] auto req : reqs) {
      count++;
    }

    auto results = context.getResults();
    auto response = results.initRes(count);

    int64_t i = 0;
    for (auto req : reqs) {
      Write::FuseFileInfo::Reader fi = req.getFi();
      capnp::Data::Reader buf_reader = req.getBuf();

      const auto chars = buf_reader.asChars();
      const char* buf = chars.begin();

      int64_t fh = fi.getFh();

      {
        std::shared_lock lock(g_fh_mutex);
        if (fh && !user_fh_sets[user].contains(fh)) {
          response[i].setErrno(EACCES);
          response[i].setRes(-1);
          return kj::READY_NOW;
        }
      }

      ssize_t written = ::pwrite(fi.getFh(), buf, req.getSize(), req.getOff());
      int err = errno;

      response[i].setRes(0);
      response[i].setErrno(err);
      response[i].setIno(req.getIno());
      response[i++].setWritten(written);
    }

    return kj::READY_NOW;
  }

  kj::Promise<void> release(ReleaseContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    Release::FuseFileInfo::Reader fi = req.getFi();
    int64_t fh = fi.getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    // std::cout << "releasing " << fh << std::endl;

    // Cleanup server-side read cache for this file handle
    remove_server_cache(fh);

    int res = ::close(fh);
    int err = errno;

    {
      std::unique_lock lock(g_fh_mutex);
      user_fh_sets[user].erase(fh);
    }

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> readdir(ReaddirContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    /**
     * example check access
     */
    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }  // END EXAMPLE

    // Entry info including stat data for client caching
    struct EntryInfo {
      std::string name;
      uint64_t ino;
      uint32_t mode;
      uint64_t size;
      uint64_t mtime;
      uint32_t mtime_nsec;
    };

    // Single pass: collect entries into vector
    std::vector<EntryInfo> collected_entries;
    collected_entries.reserve(64);  // Reasonable initial capacity

    // Helper to add entry with stat info
    auto add_entry = [&](const std::string& name, uint64_t entry_ino, const std::string& entry_path) {
      struct stat st;
      EntryInfo info{name, entry_ino, 0, 0, 0, 0};
      if (::stat(entry_path.c_str(), &st) == 0) {
        info.mode = st.st_mode;
        info.size = st.st_size;
        #ifdef __APPLE__
        info.mtime = st.st_mtimespec.tv_sec;
        info.mtime_nsec = st.st_mtimespec.tv_nsec;
        #else
        info.mtime = st.st_mtim.tv_sec;
        info.mtime_nsec = st.st_mtim.tv_nsec;
        #endif
      }
      collected_entries.push_back(info);
    };

    // Add . and ..
    add_entry(".", ino, path);
    add_entry("..", get_parent_ino(ino, path), std::filesystem::path(path).parent_path());

    // Single directory iteration - collect all entries
    std::filesystem::directory_iterator iter(
        path, std::filesystem::directory_options::skip_permission_denied);

    for (const auto& entry : iter) {
      std::string file_path = entry.path();
      std::string file_name = std::filesystem::path(file_path).filename();
      uint64_t file_ino = assign_inode(file_path);
      add_entry(file_name, file_ino, file_path);
    }

    // Add soft mounts for root
    if (ino == 1) {
      for (auto const& [dest, source] : *get_user_mounts(user)) {
        std::string file_path = std::filesystem::path(root) / source;
        uint64_t file_ino = assign_inode(file_path);
        add_entry(dest, file_ino, file_path);
      }
    }

    // Build response from collected entries
    ::capnp::List<ReaddirResponse::Entry>::Builder entries = response.initEntries(collected_entries.size());
    for (size_t i = 0; i < collected_entries.size(); i++) {
      entries[i].setName(collected_entries[i].name);
      entries[i].setIno(collected_entries[i].ino);
      entries[i].setMode(collected_entries[i].mode);
      entries[i].setSize(collected_entries[i].size);
      entries[i].setMtime(collected_entries[i].mtime);
      entries[i].setMtimeNsec(collected_entries[i].mtime_nsec);
    }

    response.setErrno(0);
    response.setRes(0);

    // std::cout << "readdir_response sent correctly: " << response_payload << std::endl;

    return kj::READY_NOW;
  }
  
  #ifdef __APPLE__
  kj::Promise<void> setxattr(SetxattrContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    int res = ::setxattr(path.c_str(), req.getName().cStr(), req.getValue().cStr(), (size_t) req.getSize(), req.getPosition(), req.getFlags());
    int err = errno;
    response.setRes(res);
    response.setErrno(err);
    
    if (res == -1) {
      return kj::READY_NOW;
    }

    response.setIno(ino);
    return kj::READY_NOW;

    // std::cout << "setxattr_response sent correctly: " << response_payload << std::endl;
  }
  #endif

  kj::Promise<void> access(AccessContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (not path.length()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    if (ino == 1) {
      response.setRes(0);      
      return kj::READY_NOW;
    }

    if (!has_inode(ino)) {
      response.setRes(-1);
      response.setErrno(ENOENT);

      return kj::READY_NOW;
    }

    int res = ::access(path.c_str(), req.getMask());
    int err = errno;

    response.setRes(res);
    response.setErrno(err);
    
    return kj::READY_NOW;
  }

  kj::Promise<void> create(CreateContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    Create::FuseFileInfo::Reader fi = req.getFi();

    uint64_t parent = req.getParent();

    std::string user_root = normalize_path(root, user, suffix);
    std::string parent_path_name = parent == 1 ? user_root : get_path_for_ino(parent);
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / req.getName().cStr();

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // std::cout << "create: open file path: " << file_path.c_str() << std::endl;
    // std::cout << "create: flags: " << fi.getFlags() << std::endl;

    int64_t flags = req.getFi().getFlags();
    int fh = ::open(file_path.c_str(), flags, req.getMode());
    int err = errno;

    // std::cout << "create: open file path: " << file_path << ", fh: " << fh
    //           << ", err: " << err << ", O_SYNC: " << ((flags & O_SYNC) == O_SYNC) << std::endl;

    if (fh == -1) {
      response.setRes(fh);
      response.setErrno(err);
      return kj::READY_NOW;
    }
    {
      std::unique_lock lock(g_fh_mutex);
      user_fh_sets[user].insert(fh);
    }

    struct stat attr;
    memset(&attr, 0, sizeof(attr));

    uint64_t file_ino = assign_inode(file_path.string());

    // e.attr_timeout = 1.0;
    // e.entry_timeout = 1.0;

    CreateResponse::FuseFileInfo::Builder fi_response = response.initFi();

    fi_response.setCacheReaddir(fi.getCacheReaddir());
    fi_response.setDirectIo(fi.getDirectIo());
    fi_response.setFh(fh);
    fi_response.setFlags(fi.getFlags());
    fi_response.setFlush(fi.getFlush());
    fi_response.setKeepCache(fi.getKeepCache());
    fi_response.setLockOwner(fi.getLockOwner());
    fi_response.setNoflush(fi.getNoflush());
    fi_response.setNonseekable(fi.getNonseekable());
    fi_response.setPadding(fi.getPadding());
    fi_response.setPollEvents(fi.getPollEvents());
    fi_response.setWritepage(fi.getWritepage());

    int res = ghostfs_stat(file_ino, &attr);

    err = errno;

    response.setIno(file_ino);

    CreateResponse::Attr::Builder attributes = response.initAttr();

    attributes.setStDev(attr.st_dev);
    attributes.setStIno(attr.st_ino);
    attributes.setStMode(attr.st_mode);
    attributes.setStNlink(attr.st_nlink);
    attributes.setStUid(attr.st_uid);
    attributes.setStGid(attr.st_gid);
    attributes.setStRdev(attr.st_rdev);
    attributes.setStSize(attr.st_size);
    attributes.setStAtime(attr.st_atime);
    attributes.setStMtime(attr.st_mtime);
    attributes.setStCtime(attr.st_ctime);
    attributes.setStBlksize(attr.st_blksize);
    attributes.setStBlocks(attr.st_blocks);

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> flush(FlushContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    Flush::FuseFileInfo::Reader fi = req.getFi();

    int64_t fh = fi.getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    // std::cout << "flushing dup(" << fh << ")" << std::endl;

    int res = ::close(dup(fh));
    int err = errno;

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> fsync(FsyncContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    Fsync::FuseFileInfo::Reader fi = req.getFi();

    int res;
    int64_t fh = fi.getFh();

    {
      std::shared_lock lock(g_fh_mutex);
      if (fh && !user_fh_sets[user].contains(fh)) {
        response.setErrno(EACCES);
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    #ifndef __APPLE__
      uint64_t datasync = req.getDatasync();
      if (datasync) {
        res = ::fdatasync(fh);
      } else {
        res = ::fsync(fh);
      }
    #else
      res = ::fsync(fh);
    #endif

    int err = errno;

    response.setErrno(err);
    response.setRes(res);

    return kj::READY_NOW;
  }

  kj::Promise<void> copyFile(CopyFileContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    std::string src_path_str = req.getSrcPath();
    std::string dst_path_str = req.getDstPath();

    // Resolve paths relative to user root
    std::string user_root = normalize_path(root, user, suffix);
    std::filesystem::path src_path = std::filesystem::path(user_root) / src_path_str;
    std::filesystem::path dst_path = std::filesystem::path(user_root) / dst_path_str;

    // Check access for both paths
    bool access_ok = check_access(root, user, suffix, src_path);
    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    access_ok = check_access(root, user, suffix, dst_path);
    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Open source file
    int src_fd = ::open(src_path.c_str(), O_RDONLY);
    if (src_fd == -1) {
      response.setErrno(errno);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Get source file size
    struct stat src_stat;
    if (::fstat(src_fd, &src_stat) == -1) {
      int err = errno;
      ::close(src_fd);
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Create/open destination file with same permissions
    int dst_fd = ::open(dst_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode);
    if (dst_fd == -1) {
      int err = errno;
      ::close(src_fd);
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    int64_t total_copied = 0;
    int res = 0;

#ifdef __APPLE__
    // macOS: use fcopyfile for efficient copy
    if (fcopyfile(src_fd, dst_fd, nullptr, COPYFILE_DATA) == 0) {
      total_copied = src_stat.st_size;
    } else {
      res = -1;
    }
#else
    // Linux: use copy_file_range for efficient copy
    off_t src_off = 0;
    off_t dst_off = 0;
    size_t remaining = src_stat.st_size;

    while (remaining > 0) {
      ssize_t copied = copy_file_range(src_fd, &src_off, dst_fd, &dst_off, remaining, 0);
      if (copied == -1) {
        res = -1;
        break;
      }
      if (copied == 0) {
        break;
      }
      total_copied += copied;
      remaining -= copied;
    }
#endif

    int err = errno;
    ::close(src_fd);
    ::close(dst_fd);

    response.setRes(res);
    response.setErrno(res == -1 ? err : 0);
    response.setBytesCopied(total_copied);

    return kj::READY_NOW;
  }

  kj::Promise<void> bulkRead(BulkReadContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    std::string path_str = req.getPath();
    int64_t offset = req.getOffset();
    uint64_t size = req.getSize();

    // Resolve path relative to user root
    std::string user_root = normalize_path(root, user, suffix);
    std::filesystem::path file_path = std::filesystem::path(user_root) / path_str;

    // Check access
    bool access_ok = check_access(root, user, suffix, file_path);
    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Open file
    int fd = ::open(file_path.c_str(), O_RDONLY);
    if (fd == -1) {
      response.setErrno(errno);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Allocate buffer
    std::vector<char> buf(size);

    // Read data
    ssize_t bytes_read = ::pread(fd, buf.data(), size, offset);
    int err = errno;

    ::close(fd);

    if (bytes_read == -1) {
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Set response
    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte*)buf.data(), bytes_read);
    capnp::Data::Reader buf_reader(buf_ptr);

    response.setBuf(buf_reader);
    response.setErrno(0);
    response.setRes(bytes_read);

    return kj::READY_NOW;
  }

  kj::Promise<void> bulkUpload(BulkUploadContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    std::string path_str = req.getPath();
    int64_t offset = req.getOffset();
    bool truncate_flag = req.getTruncate();
    uint32_t mode = req.getMode();

    capnp::Data::Reader buf_reader = req.getBuf();
    const auto chars = buf_reader.asChars();
    const char* buf = chars.begin();
    size_t buf_size = chars.size();

    // Resolve path relative to user root
    std::string user_root = normalize_path(root, user, suffix);
    std::filesystem::path file_path = std::filesystem::path(user_root) / path_str;

    // Check access
    bool access_ok = check_access(root, user, suffix, file_path);
    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Ensure parent directory exists
    std::filesystem::path parent_path = file_path.parent_path();
    if (!std::filesystem::exists(parent_path)) {
      std::error_code ec;
      std::filesystem::create_directories(parent_path, ec);
      if (ec) {
        response.setErrno(ec.value());
        response.setRes(-1);
        return kj::READY_NOW;
      }
    }

    // Open file with appropriate flags
    int flags = O_WRONLY | O_CREAT;
    if (truncate_flag) {
      flags |= O_TRUNC;
    }

    int fd = ::open(file_path.c_str(), flags, mode ? mode : 0644);
    if (fd == -1) {
      response.setErrno(errno);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Write data
    ssize_t written = ::pwrite(fd, buf, buf_size, offset);
    int err = errno;

    ::close(fd);

    if (written == -1) {
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    response.setRes(0);
    response.setErrno(0);
    response.setWritten(written);

    return kj::READY_NOW;
  }

  // Combined open+read for small file optimization
  // Reduces 2 round-trips to 1
  kj::Promise<void> openAndRead(OpenAndReadContext context) override {
    auto params = context.getParams();
    auto req = params.getReq();

    auto results = context.getResults();
    auto response = results.getRes();

    uint64_t ino = req.getIno();
    std::string path = get_path_from_ino(ino);

    if (path.empty()) {
      response.setErrno(ENOENT);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    bool access_ok = check_access(root, user, suffix, path);

    if (!access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    std::string open_path = get_path_for_ino(ino);
    if (open_path.empty()) {
      response.setRes(-1);
      response.setErrno(ENOENT);
      return kj::READY_NOW;
    }

    // Open the file
    OpenAndRead::FuseFileInfo::Reader fi = req.getFi();
    int64_t fh = ::open(open_path.c_str(), fi.getFlags());

    if (fh == -1) {
      response.setErrno(errno);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // Track file handle
    {
      std::unique_lock lock(g_fh_mutex);
      user_fh_sets[user].insert(fh);
    }

    response.setFh(fh);

    // Read the data
    size_t size = req.getSize();
    off_t off = req.getOff();

    kj::Array<kj::byte> buf = kj::heapArray<kj::byte>(size);
    ssize_t bytes_read = ::pread(fh, buf.begin(), size, off);

    if (bytes_read == -1) {
      response.setErrno(errno);
      response.setRes(-1);
      // Still return the file handle so client can close it
      return kj::READY_NOW;
    }

    // Return the data
    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr(buf.begin(), bytes_read);
    capnp::Data::Reader buf_reader(buf_ptr);
    response.setBuf(buf_reader);
    response.setRes(bytes_read);
    response.setErrno(0);

    return kj::READY_NOW;
  }

  // Any method which we don't implement will simply throw
  // an exception by default.
};

class GhostFSAuthServerImpl final : public GhostFSAuthServer::Server {
  public:

    kj::Promise<void> authorize(AuthorizeContext context) override {
      auto params = context.getParams();

      auto userPtr = params.getUser();
      std::string user(userPtr.begin(), userPtr.end());

      auto tokenPtr = params.getToken();
      std::string token(tokenPtr.begin(), tokenPtr.end());

      uint64_t retries = params.getRetries();

      std::string token_final = add_token(user, token, retries);

      auto res = context.getResults();
      res.setToken(token_final);
      
      return kj::READY_NOW;
    }

    kj::Promise<void> mount(MountContext context) override {
      auto params = context.getParams();

      auto userPtr = params.getUser();
      std::string user(userPtr.begin(), userPtr.end());

      auto sourcePtr = params.getSource();
      std::string source(sourcePtr.begin(), sourcePtr.end());

      auto destinationPtr = params.getDestination();
      std::string destination(destinationPtr.begin(), destinationPtr.end());

      soft_mount(user, source, destination);

      auto res = context.getResults();
      res.setSuccess(true);
      
      return kj::READY_NOW;
    }

    kj::Promise<void> mounts(MountsContext context) override {
      auto params = context.getParams();

      auto userPtr = params.getUser();
      std::string user(userPtr.begin(), userPtr.end());

      std::map<std::string, std::string>* user_mounts = get_user_mounts(user);

      auto res = context.getResults();
      auto mounts = res.initMounts(user_mounts->size());

      int64_t i = 0;
      for ([[maybe_unused]] auto const& [dest, source] : *user_mounts) {
        mounts.set(i++, dest);
      }
      
      return kj::READY_NOW;
    }

    kj::Promise<void> unmount(UnmountContext context) override {
      auto params = context.getParams();

      auto userPtr = params.getUser();
      std::string user(userPtr.begin(), userPtr.end());

      auto destinationPtr = params.getDestination();
      std::string destination(destinationPtr.begin(), destinationPtr.end());

      soft_unmount(user, destination);

      auto res = context.getResults();
      res.setSuccess(true);
      
      return kj::READY_NOW;
    }

    kj::Promise<void> unmountAll(UnmountAllContext context) override {
      auto params = context.getParams();

      auto userPtr = params.getUser();
      std::string user(userPtr.begin(), userPtr.end());

      soft_unmount(user);

      auto res = context.getResults();
      res.setSuccess(true);
      
      return kj::READY_NOW;
    }
};

int rpc_add_token(uint16_t port, std::string user, std::string token, int64_t retries) {
  capnp::EzRpcClient rpc("127.0.0.1", port);

  auto& waitScope = rpc.getWaitScope();
  GhostFSAuthServer::Client authClient = rpc.getMain<GhostFSAuthServer>();

  auto request = authClient.authorizeRequest();

  request.setUser(user);
  request.setToken(token);
  request.setRetries(retries);

  auto promise = request.send();
  auto result = promise.wait(waitScope);
  auto tokenPtr = result.getToken();

  std::string tokenFinal(tokenPtr.begin(), tokenPtr.end());
  std::cout << tokenFinal << std::endl;

  return 0;
}

int rpc_mount(uint16_t port, std::string user, std::string source, std::string destination) {
  capnp::EzRpcClient rpc("127.0.0.1", port);

  auto& waitScope = rpc.getWaitScope();
  GhostFSAuthServer::Client authClient = rpc.getMain<GhostFSAuthServer>();

  auto request = authClient.mountRequest();

  request.setUser(user);
  request.setSource(source);
  request.setDestination(destination);

  auto promise = request.send();
  [[maybe_unused]] auto result = promise.wait(waitScope);

  return 0;
}

int rpc_print_mounts(uint16_t port, std::string user) {
  capnp::EzRpcClient rpc("127.0.0.1", port);

  auto& waitScope = rpc.getWaitScope();
  GhostFSAuthServer::Client authClient = rpc.getMain<GhostFSAuthServer>();

  auto request = authClient.mountsRequest();

  request.setUser(user);

  auto promise = request.send();
  auto result = promise.wait(waitScope);

  capnp::List<capnp::Text>::Reader mounts = result.getMounts();

  for (std::string mount : mounts) {
    std::cout << mount << std::endl;
  }

  return 0;
}

int rpc_unmount(uint16_t port, std::string user, std::string destination) {
  capnp::EzRpcClient rpc("127.0.0.1", port);

  auto& waitScope = rpc.getWaitScope();
  GhostFSAuthServer::Client authClient = rpc.getMain<GhostFSAuthServer>();

  auto request = authClient.unmountRequest();

  request.setUser(user);
  request.setDestination(destination);

  auto promise = request.send();
  [[maybe_unused]] auto result = promise.wait(waitScope);

  return 0;
}

int rpc_unmount_all(uint16_t port, std::string user) {
  capnp::EzRpcClient rpc("127.0.0.1", port);

  auto& waitScope = rpc.getWaitScope();
  GhostFSAuthServer::Client authClient = rpc.getMain<GhostFSAuthServer>();

  auto request = authClient.unmountAllRequest();
  request.setUser(user);

  auto promise = request.send();
  [[maybe_unused]] auto result = promise.wait(waitScope);

  return 0;
}

class GhostFSAuthImpl final : public GhostFSAuth::Server {
  std::string root;
  std::string suffix;

public:
  explicit GhostFSAuthImpl(std::string _root, std::string _suffix)
      : root(std::move(_root)), suffix(std::move(_suffix)) {}

  kj::Promise<void> auth(AuthContext context) override {
    auto params = context.getParams();

    auto userPtr = params.getUser();
    std::string user(userPtr.begin(), userPtr.end());

    auto tokenPtr = params.getToken();
    std::string token(tokenPtr.begin(), tokenPtr.end());

    // TODO: in previous WebSocket implementation userId
    // wasn't equal to user's subdirectory, this needs attention
    bool isValid = authenticate(token, user);
    auto res = context.getResults();
    
    res.setAuthSuccess(isValid);

    if (isValid) {
      res.setGhostFs(kj::heap<GhostFSImpl>(user, root, suffix));
    }

    return kj::READY_NOW;
  }
};

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        exit(EXIT_FAILURE);
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

int start_rpc_server(std::string bind, int port, int auth_port, std::string root,
                     std::string suffix, std::string key_file, std::string cert_file) {
  if (root.length() > 0) {
    if (not std::filesystem::is_directory(root)) {
      std::error_code ec;
      std::filesystem::create_directories(root, ec);
      if (ec || !std::filesystem::is_directory(root)) {
        std::cout << "ERROR: failed to create directory " << '"' << root << '"' << std::endl;
        return 1;
      }
      std::cout << "Created root directory: " << root << std::endl;
    };
  }

  kj::_::Debug::setLogLevel(kj::_::Debug::Severity::ERROR);

  std::string key = key_file.length() ? read_file(key_file) : "";
  std::string cert = cert_file.length() ? read_file(cert_file) : "";

  std::cout << "Starting GhostFS server on " << bind << ":" << port << "..." << std::endl;
  std::cout << "Starting GhostFS auth server on port " << auth_port << "..." << std::endl;

  /**
   * Capnp RPC server. 
   */

  auto ioContext = kj::setupAsyncIo();

  capnp::TwoPartyServer server(kj::heap<GhostFSAuthImpl>(root, suffix));
  capnp::TwoPartyServer auth_server(kj::heap<GhostFSAuthServerImpl>());

  auto auth_address = ioContext.provider->getNetwork()
      .parseAddress("127.0.0.1", auth_port).wait(ioContext.waitScope);

  auto auth_listener = auth_address->listen();
  auto auth_listen_promise = auth_server.listen(*auth_listener);

  if (key_file.length() or cert_file.length()) {
    kj::TlsKeypair keypair { kj::TlsPrivateKey(key), kj::TlsCertificate(cert) };
    
    kj::TlsContext::Options options;
    options.defaultKeypair = keypair;
    options.useSystemTrustStore = false;
    // using TlsErrorHandler = kj::Function<void(kj::Exception&&)>;
    options.acceptErrorHandler = [](kj::Exception &&e) {
      std::cout << "Error: " << e.getDescription().cStr() << std::endl;
    };

    kj::TlsContext tlsContext(kj::mv(options));

    auto network = tlsContext.wrapNetwork(ioContext.provider->getNetwork());
    auto address = network->parseAddress(bind, port).wait(ioContext.waitScope);
    auto listener = address->listen();
    auto listen_promise = server.listen(*listener);

    listen_promise.wait(ioContext.waitScope);
  } else {
    auto address = ioContext.provider->getNetwork()
      .parseAddress(bind, port).wait(ioContext.waitScope);

    auto listener = address->listen();
    auto listen_promise = server.listen(*listener);
    
    listen_promise.wait(ioContext.waitScope);
  }

  return 0;
}

// Start only the auth RPC server in a detached thread
void start_auth_server_async(uint16_t auth_port) {
  std::thread([auth_port]() {
    kj::_::Debug::setLogLevel(kj::_::Debug::Severity::ERROR);

    auto ioContext = kj::setupAsyncIo();
    capnp::TwoPartyServer auth_server(kj::heap<GhostFSAuthServerImpl>());

    auto auth_address = ioContext.provider->getNetwork()
        .parseAddress("127.0.0.1", auth_port)
        .wait(ioContext.waitScope);

    auto auth_listener = auth_address->listen();
    std::cout << "Auth server started on port " << auth_port << std::endl;

    auth_server.listen(*auth_listener).wait(ioContext.waitScope);
  }).detach();
}

// Start the full RPC server (main + auth) in a detached thread
void start_rpc_server_async(std::string bind, uint16_t port, uint16_t auth_port,
                            std::string root, std::string suffix,
                            std::string key_file, std::string cert_file) {
  std::thread([bind, port, auth_port, root, suffix, key_file, cert_file]() {
    if (root.length() > 0) {
      if (!std::filesystem::is_directory(root)) {
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
        if (ec || !std::filesystem::is_directory(root)) {
          std::cerr << "ERROR: failed to create directory " << '"' << root << '"' << std::endl;
          return;
        }
        std::cout << "Created root directory: " << root << std::endl;
      }
    }

    kj::_::Debug::setLogLevel(kj::_::Debug::Severity::ERROR);

    std::string key = key_file.length() ? read_file(key_file) : "";
    std::string cert = cert_file.length() ? read_file(cert_file) : "";

    std::cout << "Starting GhostFS RPC server on " << bind << ":" << port << "..." << std::endl;
    std::cout << "Starting GhostFS auth server on port " << auth_port << "..." << std::endl;

    auto ioContext = kj::setupAsyncIo();

    capnp::TwoPartyServer server(kj::heap<GhostFSAuthImpl>(root, suffix));
    capnp::TwoPartyServer auth_server(kj::heap<GhostFSAuthServerImpl>());

    auto auth_address = ioContext.provider->getNetwork()
        .parseAddress("127.0.0.1", auth_port).wait(ioContext.waitScope);

    auto auth_listener = auth_address->listen();
    auto auth_listen_promise = auth_server.listen(*auth_listener);

    if (key_file.length() || cert_file.length()) {
      kj::TlsKeypair keypair { kj::TlsPrivateKey(key), kj::TlsCertificate(cert) };

      kj::TlsContext::Options options;
      options.defaultKeypair = keypair;
      options.useSystemTrustStore = false;
      options.acceptErrorHandler = [](kj::Exception &&e) {
        std::cerr << "TLS Error: " << e.getDescription().cStr() << std::endl;
      };

      kj::TlsContext tlsContext(kj::mv(options));

      auto network = tlsContext.wrapNetwork(ioContext.provider->getNetwork());
      auto address = network->parseAddress(bind, port).wait(ioContext.waitScope);
      auto listener = address->listen();
      auto listen_promise = server.listen(*listener);

      listen_promise.wait(ioContext.waitScope);
    } else {
      auto address = ioContext.provider->getNetwork()
          .parseAddress(bind, port).wait(ioContext.waitScope);

      auto listener = address->listen();
      auto listen_promise = server.listen(*listener);

      listen_promise.wait(ioContext.waitScope);
    }
  }).detach();
}