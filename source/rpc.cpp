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

#include <filesystem>
#include <map>
#include <set>
#include <vector>

// Global file handle sets per user (shared across all connections for same user)
// This allows multi-threaded FUSE clients to share file handles across connections
std::map<std::string, std::set<int64_t>> user_fh_sets;

class GhostFSImpl final : public GhostFS::Server {
  std::string user;
  std::string root;
  std::string suffix;

  std::string get_path_from_ino(uint64_t ino) {
    // ROOT
    if (ino == 1) {
      return normalize_path(root, user, suffix);
    } else if (ino_to_path.contains(ino)) {
      return ino_to_path[ino];
    }
    return "";
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
      std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
      std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
      file_path = parent_path / std::filesystem::path(name);
    }

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    uint64_t ino;

    if (not path_to_ino.contains(file_path)) {
      ino = ++current_ino;
      ino_to_path[ino] = file_path;
      path_to_ino[file_path] = ino;
    } else {
      ino = path_to_ino[file_path];
    }

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

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
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

    if (not ino_to_path.contains(ino)) {
      // Parent is unknown
      err = errno;
      response.setErrno(err);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    std::string file_path = ino_to_path[ino];

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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / req.getName().cStr();

    bool access_ok = check_access(root, user, suffix, file_path);

    if (not access_ok) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    uint64_t file_ino;

    file_ino = ++current_ino;
    ino_to_path[file_ino] = file_path;
    path_to_ino[file_path] = file_ino;

    int fh = ::mknod(file_path.c_str(), req.getMode(), req.getRdev());
    int err = errno;

    if (fh == -1) {      
      ino_to_path.erase(file_ino);
      path_to_ino.erase(file_path);
      
      response.setErrno(err);
      response.setRes(fh);
      return kj::READY_NOW;
    } else {
      user_fh_sets[user].insert(fh);

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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
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
      user_fh_sets[user].insert(fh);

      struct stat attr;
      memset(&attr, 0, sizeof(attr));

      uint64_t file_ino;

      file_ino = ++current_ino;
      ino_to_path[file_ino] = file_path;
      path_to_ino[file_path] = file_ino;

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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
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

    int res = ::readlink(ino_to_path[req.getIno()].c_str(), buf, sizeof(buf) - 1);  // Decrease the buffer size by 1
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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
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

      uint64_t file_ino;

      file_ino = ++current_ino;
      ino_to_path[file_ino] = file_path;
      path_to_ino[file_path] = file_ino;

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

    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
    std::filesystem::path parent_path = std::filesystem::path(parent_path_name);
    std::filesystem::path file_path = parent_path / std::filesystem::path(name);

    std::string newparent_path_name = newparent == 1 ? user_root : ino_to_path[newparent];
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

    // fix ino to path
    int64_t ino = path_to_ino[file_path];
    ino_to_path[ino] = newfile_path;
    path_to_ino[newfile_path] = ino;
    path_to_ino.erase(file_path);

    // fix ino to path recursively if we rename a directory
    // Use symlink_status to check if it's actually a directory (not a symlink to one)
    // This prevents re-entry deadlocks when symlinks point back to the FUSE mount
    auto status = std::filesystem::symlink_status(newfile_path);
    if (std::filesystem::is_directory(status)) {
      for(const auto& entry: std::filesystem::recursive_directory_iterator(newfile_path)) {
        std::filesystem::path new_name = entry.path();
        std::filesystem::path relative = std::filesystem::relative(new_name, newfile_path);
        std::filesystem::path old_name = file_path / relative;

        // Check if old_name exists in path_to_ino before accessing to prevent auto-vivification
        if (path_to_ino.contains(old_name)) {
          int64_t ino = path_to_ino[old_name];
          ino_to_path[ino] = new_name;
          path_to_ino[new_name] = ino;
          path_to_ino.erase(old_name);
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

    if (not ino_to_path.contains(req.getIno())) {
      // File is unknown
      response.setRes(-1);
      response.setErrno(ENOENT);
      return kj::READY_NOW;
    }

    response.setIno(req.getIno());

    Open::FuseFileInfo::Reader fi = req.getFi();

    int64_t fh = ::open(ino_to_path[req.getIno()].c_str(), fi.getFlags());

    // std::cout << "open fh: " << fh << ", path: " << path << std::endl; 

    int err = errno;
    response.setErrno(err);
    response.setRes(fh);

    if (fh == -1) {
      response.setRes(fh);
      return kj::READY_NOW;
    }

    user_fh_sets[user].insert(fh);

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

    if (not ino_to_path.contains(ino)) {
      // File is unknown
      response.setRes(-1);
      response.setErrno(ENOENT);
      return kj::READY_NOW;
    }

    size_t size = req.getSize();
    off_t off = req.getOff();

    // Use heap allocation instead of VLA to prevent stack overflow with large reads
    std::vector<char> buf(size);
    Read::FuseFileInfo::Reader fi = req.getFi();

    int64_t fh = fi.getFh();

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    ssize_t res = ::pread(fh, buf.data(), size, off);
    uint64_t bytesRead = res > 0 ? res : 0;

    int err = errno;

    // std::cout << "read_response setting ptrs" << std::endl;
    // std::cout << "read_request size: " << size << ", read: " << bytesRead
    //          << ", res: " << res << ", errno: " << err
    //          << ", fh: " << fi.getFh() << std::endl;

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte*)buf.data(), bytesRead);
    capnp::Data::Reader buf_reader(buf_ptr);

    response.setBuf(buf_reader);
    response.setErrno(err);
    response.setRes(res);

    // std::cout << "read_response sent" << std::endl;

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

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
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

      if (fh and not user_fh_sets[user].contains(fh)) {
        response[i].setErrno(EACCES);
        response[i].setRes(-1);
        return kj::READY_NOW;
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

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
    }

    // std::cout << "releasing " << fh << std::endl;

    int res = ::close(fh);
    int err = errno;

    user_fh_sets[user].erase(fh);

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

    uint64_t length = 2;

    std::filesystem::directory_iterator iter(
        path, std::filesystem::directory_options::skip_permission_denied);

    for ([[maybe_unused]] const auto& entry : iter) {
      length++;
    }

    if (ino == 1) {
      for([[maybe_unused]] auto const& mount: *get_user_mounts(user)) {
        length++;
      }
    }

    ::capnp::List<ReaddirResponse::Entry>::Builder entries = response.initEntries(length);

    entries[0].setName(".");
    entries[0].setIno(ino);
    entries[1].setName("..");
    entries[1].setIno(get_parent_ino(ino, path));

    uint64_t index = 2;

    // TODO: Find out how we can reuse the iterator from previous step
    iter = std::filesystem::directory_iterator(
        path, std::filesystem::directory_options::skip_permission_denied);

    for (const auto& entry : iter) {
      std::string file_path = entry.path();
      std::string file_name = std::filesystem::path(file_path).filename();

      uint64_t file_ino;

      if (not path_to_ino.contains(file_path)) {
        file_ino = ++current_ino;
        ino_to_path[file_ino] = file_path;
        path_to_ino[file_path] = file_ino;
      } else {
        file_ino = path_to_ino[file_path];
      }

      entries[index].setName(file_name);
      entries[index].setIno(file_ino);

      index++;
    }

    if (ino == 1) {
      for([[maybe_unused]] auto const& mount: *get_user_mounts(user)) {
        std::string destination = mount.first;
        std::string source = mount.second;
        std::string file_path = std::filesystem::path(root) / source;

        uint64_t file_ino;

        if (not path_to_ino.contains(file_path)) {
          file_ino = ++current_ino;
          ino_to_path[file_ino] = file_path;
          path_to_ino[file_path] = file_ino;
        } else {
          file_ino = path_to_ino[file_path];
        }

        entries[index].setName(destination);
        entries[index].setIno(file_ino);

        index++;
      }
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

    if (not ino_to_path.contains(ino)) {
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
    std::string parent_path_name = parent == 1 ? user_root : ino_to_path[parent];
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
    user_fh_sets[user].insert(fh);

    struct stat attr;
    memset(&attr, 0, sizeof(attr));

    uint64_t file_ino;

    file_ino = ++current_ino;
    ino_to_path[file_ino] = file_path;
    path_to_ino[file_path] = file_ino;

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

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
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

    if (fh and not user_fh_sets[user].contains(fh)) {
      response.setErrno(EACCES);
      response.setRes(-1);
      return kj::READY_NOW;
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