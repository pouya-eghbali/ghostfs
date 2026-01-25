// WinFSP implementation for Windows
#ifdef _WIN32

#include <ghostfs/fs.h>
#include <ghostfs/fs_common.h>

#include <windows.h>
#include <winfsp/winfsp.h>
#include <sddl.h>

#include <filesystem>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Cap'n Proto
#include <capnp/message.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/serialize-packed.h>
#include <kj/async-io.h>
#include <kj/async.h>
#include <kj/compat/tls.h>

// Cap'n Proto schemas
#include <access.capnp.h>
#include <access.response.capnp.h>
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
#include <unlink.capnp.h>
#include <unlink.response.capnp.h>
#include <write.capnp.h>
#include <write.response.capnp.h>

using namespace ghostfs;

// Unix mode constants (for compatibility with server)
#define S_IFMT   0170000
#define S_IFDIR  0040000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_IWUSR  0200

// POSIX open flags (for compatibility with server)
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040

// FUSE setattr flags
#define FUSE_SET_ATTR_SIZE 8

// File context for each open file
struct GhostFSFileContext {
  uint64_t ino;
  uint64_t fh;
  std::wstring path;
  bool is_directory;
};

// Global WinFSP filesystem state
static FSP_FILE_SYSTEM *g_FileSystem = nullptr;
static WCHAR g_VolumeLabel[32] = L"GhostFS";

// Helper functions

// Convert errno to NTSTATUS
static NTSTATUS errno_to_ntstatus(int err) {
  switch (err) {
    case 0:        return STATUS_SUCCESS;
    case ENOENT:   return STATUS_OBJECT_NAME_NOT_FOUND;
    case EEXIST:   return STATUS_OBJECT_NAME_COLLISION;
    case EACCES:   return STATUS_ACCESS_DENIED;
    case EPERM:    return STATUS_ACCESS_DENIED;
    case ENOTDIR:  return STATUS_NOT_A_DIRECTORY;
    case EISDIR:   return STATUS_FILE_IS_A_DIRECTORY;
    case ENOTEMPTY:return STATUS_DIRECTORY_NOT_EMPTY;
    case ENOSPC:   return STATUS_DISK_FULL;
    case ENOMEM:   return STATUS_INSUFFICIENT_RESOURCES;
    case EINVAL:   return STATUS_INVALID_PARAMETER;
    case EBUSY:    return STATUS_DEVICE_BUSY;
    case EIO:      return STATUS_IO_DEVICE_ERROR;
    case ETIMEDOUT:return STATUS_TIMEOUT;
    case ENOSYS:   return STATUS_NOT_IMPLEMENTED;
    default:       return STATUS_UNSUCCESSFUL;
  }
}

// Convert wstring to UTF-8 string
static std::string wstring_to_utf8(const std::wstring& wstr) {
  if (wstr.empty()) return std::string();
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
  std::string str(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, nullptr, nullptr);
  return str;
}

// Convert UTF-8 string to wstring
static std::wstring utf8_to_wstring(const std::string& str) {
  if (str.empty()) return std::wstring();
  int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
  std::wstring wstr(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
  return wstr;
}

// Convert Unix mode to Windows file attributes
static UINT32 mode_to_attributes(uint32_t mode) {
  UINT32 attr = 0;
  if (S_ISDIR(mode)) {
    attr |= FILE_ATTRIBUTE_DIRECTORY;
  }
  if (!(mode & S_IWUSR)) {
    attr |= FILE_ATTRIBUTE_READONLY;
  }
  return attr ? attr : FILE_ATTRIBUTE_NORMAL;
}

// Convert Unix timestamp to Windows FILETIME (100-nanosecond intervals since 1601)
static UINT64 unix_to_filetime(int64_t unix_time) {
  // Unix epoch is 1970-01-01, Windows FILETIME epoch is 1601-01-01
  // Difference is 11644473600 seconds
  return (unix_time + 11644473600LL) * 10000000LL;
}

// Convert Windows path to Unix-style path for RPC
static std::string normalize_path(PWSTR path) {
  if (!path || !path[0]) {
    return "/";
  }
  std::wstring wpath(path);
  // Replace backslashes with forward slashes
  for (auto& c : wpath) {
    if (c == L'\\') c = L'/';
  }
  // Ensure leading slash
  if (wpath[0] != L'/') {
    wpath = L"/" + wpath;
  }
  return wstring_to_utf8(wpath);
}

// Get inode from path via lookup RPC
static int lookup_path(const std::string& path, uint64_t& out_ino, uint32_t& out_mode, uint64_t& out_size) {
  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    // Split path into components and walk the tree
    std::filesystem::path p(path);
    uint64_t current_ino = 1;  // Root inode

    for (const auto& component : p) {
      if (component == "/" || component.empty()) continue;

      auto request = rpc.client->lookupRequest();
      Lookup::Builder lookup = request.getReq();
      lookup.setParent(current_ino);
      lookup.setName(component.string().c_str());

      auto result = waitWithTimeout(request.send(), timer, waitScope);
      auto response = result.getRes();

      if (response.getRes() == -1) {
        return response.getErrno();
      }

      current_ino = response.getIno();
      out_mode = response.getAttr().getStMode();
      out_size = response.getAttr().getStSize();
    }

    out_ino = current_ino;
    return 0;
  } catch (const kj::Exception& e) {
    std::cerr << "lookup_path error: " << e.getDescription().cStr() << std::endl;
    return ETIMEDOUT;
  }
}

// Fill Cap'n Proto file info from WinFSP parameters
template <class T>
static void fillFileInfo(T *fuseFileInfo, UINT32 flags, uint64_t fh) {
  fuseFileInfo->setFlags(flags);
  fuseFileInfo->setWritepage(0);
  fuseFileInfo->setDirectIo(0);
  fuseFileInfo->setKeepCache(0);
  fuseFileInfo->setFlush(0);
  fuseFileInfo->setNonseekable(0);
  fuseFileInfo->setPadding(0);
  fuseFileInfo->setFh(fh);
  fuseFileInfo->setLockOwner(0);
}

// WinFSP Callbacks

static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM *FileSystem, FSP_FSCTL_VOLUME_INFO *VolumeInfo) {
  VolumeInfo->TotalSize = 1024ULL * 1024 * 1024 * 100;  // 100 GB
  VolumeInfo->FreeSize = 1024ULL * 1024 * 1024 * 50;    // 50 GB
  VolumeInfo->VolumeLabelLength = (UINT16)(wcslen(g_VolumeLabel) * sizeof(WCHAR));
  memcpy(VolumeInfo->VolumeLabel, g_VolumeLabel, VolumeInfo->VolumeLabelLength);
  return STATUS_SUCCESS;
}

static NTSTATUS GetSecurityByName(
    FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName,
    PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T *PSecurityDescriptorSize) {

  std::cout << "[WinFSP] GetSecurityByName called" << std::endl;
  std::cout.flush();
  std::string path = normalize_path(FileName);

  uint64_t ino;
  uint32_t mode;
  uint64_t size;
  int err = lookup_path(path, ino, mode, size);

  if (err != 0) {
    return errno_to_ntstatus(err);
  }

  if (PFileAttributes) {
    *PFileAttributes = mode_to_attributes(mode);
  }

  // Return a default security descriptor
  if (PSecurityDescriptorSize) {
    PSECURITY_DESCRIPTOR DefaultSd = nullptr;
    ULONG DefaultSdSize = 0;

    // Create a default security descriptor allowing full access
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;WD)",  // Allow full access to everyone
            SDDL_REVISION_1,
            &DefaultSd,
            &DefaultSdSize)) {
      if (SecurityDescriptor && *PSecurityDescriptorSize >= DefaultSdSize) {
        memcpy(SecurityDescriptor, DefaultSd, DefaultSdSize);
      }
      *PSecurityDescriptorSize = DefaultSdSize;
      LocalFree(DefaultSd);
    } else {
      *PSecurityDescriptorSize = 0;
    }
  }

  return STATUS_SUCCESS;
}

static NTSTATUS Create(
    FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    UINT32 FileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    UINT64 AllocationSize,
    PVOID *PFileContext,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  std::cout << "[WinFSP] Create called" << std::endl;
  std::cout.flush();
  std::string path = normalize_path(FileName);
  bool is_directory = (CreateOptions & FILE_DIRECTORY_FILE) != 0;

  // Get parent directory inode
  std::filesystem::path p(path);
  std::string parent_path = p.parent_path().string();
  if (parent_path.empty()) parent_path = "/";
  std::string name = p.filename().string();

  uint64_t parent_ino;
  uint32_t parent_mode;
  uint64_t parent_size;
  int err = lookup_path(parent_path, parent_ino, parent_mode, parent_size);
  if (err != 0) {
    return errno_to_ntstatus(err);
  }

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    uint64_t ino;
    uint64_t fh = 0;
    uint32_t mode;
    uint64_t size = 0;
    uint64_t atime, mtime, ctime;

    if (is_directory) {
      // Create directory via mkdir RPC
      auto request = rpc.client->mkdirRequest();
      Mkdir::Builder mkdir = request.getReq();
      mkdir.setParent(parent_ino);
      mkdir.setName(name.c_str());
      mkdir.setMode(0755 | S_IFDIR);

      auto result = waitWithTimeout(request.send(), timer, waitScope);
      auto response = result.getRes();

      if (response.getRes() == -1) {
        return errno_to_ntstatus(response.getErrno());
      }

      ino = response.getIno();
      auto attr = response.getAttr();
      mode = attr.getStMode();
      size = attr.getStSize();
      atime = attr.getStAtime();
      mtime = attr.getStMtime();
      ctime = attr.getStCtime();
    } else {
      // Create file via create RPC
      auto request = rpc.client->createRequest();
      Create::Builder create = request.getReq();
      Create::FuseFileInfo::Builder fuseFileInfo = create.initFi();

      create.setParent(parent_ino);
      create.setName(name.c_str());
      create.setMode(0644 | S_IFREG);
      fillFileInfo(&fuseFileInfo, O_CREAT | O_RDWR, 0);

      auto result = waitWithTimeout(request.send(), timer, waitScope);
      auto response = result.getRes();

      if (response.getRes() == -1) {
        return errno_to_ntstatus(response.getErrno());
      }

      ino = response.getIno();
      fh = response.getFi().getFh();
      auto attr = response.getAttr();
      mode = attr.getStMode();
      size = attr.getStSize();
      atime = attr.getStAtime();
      mtime = attr.getStMtime();
      ctime = attr.getStCtime();
    }

    // Allocate file context
    GhostFSFileContext *ctx = new GhostFSFileContext();
    ctx->ino = ino;
    ctx->fh = fh;
    ctx->path = utf8_to_wstring(path);
    ctx->is_directory = is_directory;
    *PFileContext = ctx;

    // Fill file info
    FileInfo->FileAttributes = mode_to_attributes(mode);
    FileInfo->ReparseTag = 0;
    FileInfo->AllocationSize = (size + 4095) & ~4095ULL;
    FileInfo->FileSize = size;
    FileInfo->CreationTime = unix_to_filetime(ctime);
    FileInfo->LastAccessTime = unix_to_filetime(atime);
    FileInfo->LastWriteTime = unix_to_filetime(mtime);
    FileInfo->ChangeTime = unix_to_filetime(mtime);
    FileInfo->IndexNumber = ino;
    FileInfo->HardLinks = 1;

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Create error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS Open(
    FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    PVOID *PFileContext,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  std::cout << "[WinFSP] Open called" << std::endl;
  std::cout.flush();
  std::string path = normalize_path(FileName);

  uint64_t ino;
  uint32_t mode;
  uint64_t size;
  int err = lookup_path(path, ino, mode, size);
  if (err != 0) {
    return errno_to_ntstatus(err);
  }

  bool is_directory = S_ISDIR(mode);
  uint64_t fh = 0;

  // Open the file/directory on the server
  if (!is_directory) {
    try {
      auto& rpc = getRpc();
      auto& waitScope = rpc.ioContext->waitScope;
      auto& timer = rpc.getTimer();

      auto request = rpc.client->openRequest();
      Open::Builder open = request.getReq();
      Open::FuseFileInfo::Builder fuseFileInfo = open.initFi();

      open.setIno(ino);

      UINT32 flags = 0;
      if (GrantedAccess & GENERIC_READ) flags |= O_RDONLY;
      if (GrantedAccess & GENERIC_WRITE) flags |= O_WRONLY;
      if ((GrantedAccess & GENERIC_READ) && (GrantedAccess & GENERIC_WRITE)) flags = O_RDWR;
      fillFileInfo(&fuseFileInfo, flags, 0);

      auto result = waitWithTimeout(request.send(), timer, waitScope);
      auto response = result.getRes();

      if (response.getRes() == -1) {
        return errno_to_ntstatus(response.getErrno());
      }

      fh = response.getFi().getFh();
    } catch (const kj::Exception& e) {
      std::cerr << "Open error: " << e.getDescription().cStr() << std::endl;
      return STATUS_TIMEOUT;
    }
  }

  // Get file attributes
  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->getattrRequest();
    Getattr::Builder getattr = request.getReq();
    Getattr::FuseFileInfo::Builder fuseFileInfo = getattr.initFi();

    getattr.setIno(ino);
    fillFileInfo(&fuseFileInfo, 0, fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    auto attr = response.getAttr();

    // Allocate file context
    GhostFSFileContext *ctx = new GhostFSFileContext();
    ctx->ino = ino;
    ctx->fh = fh;
    ctx->path = utf8_to_wstring(path);
    ctx->is_directory = is_directory;
    *PFileContext = ctx;

    // Fill file info
    FileInfo->FileAttributes = mode_to_attributes(attr.getStMode());
    FileInfo->ReparseTag = 0;
    FileInfo->AllocationSize = (attr.getStSize() + 4095) & ~4095ULL;
    FileInfo->FileSize = attr.getStSize();
    FileInfo->CreationTime = unix_to_filetime(attr.getStCtime());
    FileInfo->LastAccessTime = unix_to_filetime(attr.getStAtime());
    FileInfo->LastWriteTime = unix_to_filetime(attr.getStMtime());
    FileInfo->ChangeTime = unix_to_filetime(attr.getStMtime());
    FileInfo->IndexNumber = ino;
    FileInfo->HardLinks = attr.getStNlink();

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Open getattr error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static VOID Close(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext) {
  (void)FileSystem;
  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  if (ctx->fh != 0 && !ctx->is_directory) {
    try {
      auto& rpc = getRpc();
      auto& waitScope = rpc.ioContext->waitScope;
      auto& timer = rpc.getTimer();

      auto request = rpc.client->releaseRequest();
      Release::Builder release = request.getReq();
      Release::FuseFileInfo::Builder fuseFileInfo = release.initFi();

      release.setIno(ctx->ino);
      fillFileInfo(&fuseFileInfo, 0, ctx->fh);

      waitWithTimeout(request.send(), timer, waitScope);
    } catch (const kj::Exception& e) {
      std::cerr << "Close error: " << e.getDescription().cStr() << std::endl;
    }
  }

  delete ctx;
}

static NTSTATUS Read(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    PULONG PBytesTransferred) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->readRequest();
    Read::Builder read = request.getReq();
    Read::FuseFileInfo::Builder fuseFileInfo = read.initFi();

    read.setIno(ctx->ino);
    read.setSize(Length);
    read.setOff(Offset);
    fillFileInfo(&fuseFileInfo, O_RDONLY, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      *PBytesTransferred = 0;
      return errno_to_ntstatus(response.getErrno());
    }

    capnp::Data::Reader buf_reader = response.getBuf();
    size_t bytes_read = buf_reader.size();
    if (bytes_read > Length) bytes_read = Length;
    memcpy(Buffer, buf_reader.begin(), bytes_read);
    *PBytesTransferred = (ULONG)bytes_read;

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Read error: " << e.getDescription().cStr() << std::endl;
    *PBytesTransferred = 0;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS Write(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    BOOLEAN WriteToEndOfFile,
    BOOLEAN ConstrainedIo,
    PULONG PBytesTransferred,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->writeRequest();
    Write::Builder write = request.getReq();
    Write::FuseFileInfo::Builder fuseFileInfo = write.initFi();

    kj::ArrayPtr<kj::byte> buf_ptr = kj::arrayPtr((kj::byte *)Buffer, Length);
    capnp::Data::Reader buf_reader(buf_ptr);

    write.setIno(ctx->ino);
    write.setBuf(buf_reader);
    write.setSize(Length);
    write.setOff(Offset);
    fillFileInfo(&fuseFileInfo, O_WRONLY, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      *PBytesTransferred = 0;
      return errno_to_ntstatus(response.getErrno());
    }

    *PBytesTransferred = response.getWritten();

    // Get updated file info
    auto getattrRequest = rpc.client->getattrRequest();
    Getattr::Builder getattr = getattrRequest.getReq();
    Getattr::FuseFileInfo::Builder getattrFi = getattr.initFi();
    getattr.setIno(ctx->ino);
    fillFileInfo(&getattrFi, 0, ctx->fh);

    auto getattrResult = waitWithTimeout(getattrRequest.send(), timer, waitScope);
    auto getattrResponse = getattrResult.getRes();

    if (getattrResponse.getRes() == 0) {
      auto attr = getattrResponse.getAttr();
      FileInfo->FileAttributes = mode_to_attributes(attr.getStMode());
      FileInfo->FileSize = attr.getStSize();
      FileInfo->AllocationSize = (attr.getStSize() + 4095) & ~4095ULL;
      FileInfo->LastWriteTime = unix_to_filetime(attr.getStMtime());
      FileInfo->ChangeTime = unix_to_filetime(attr.getStMtime());
    }

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Write error: " << e.getDescription().cStr() << std::endl;
    *PBytesTransferred = 0;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS Flush(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  if (ctx->is_directory) {
    return STATUS_SUCCESS;
  }

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->fsyncRequest();
    Fsync::Builder fsync = request.getReq();
    Fsync::FuseFileInfo::Builder fuseFileInfo = fsync.initFi();

    fsync.setIno(ctx->ino);
    fsync.setDatasync(0);
    fillFileInfo(&fuseFileInfo, 0, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Flush error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS GetFileInfo(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->getattrRequest();
    Getattr::Builder getattr = request.getReq();
    Getattr::FuseFileInfo::Builder fuseFileInfo = getattr.initFi();

    getattr.setIno(ctx->ino);
    fillFileInfo(&fuseFileInfo, 0, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    auto attr = response.getAttr();

    FileInfo->FileAttributes = mode_to_attributes(attr.getStMode());
    FileInfo->ReparseTag = 0;
    FileInfo->AllocationSize = (attr.getStSize() + 4095) & ~4095ULL;
    FileInfo->FileSize = attr.getStSize();
    FileInfo->CreationTime = unix_to_filetime(attr.getStCtime());
    FileInfo->LastAccessTime = unix_to_filetime(attr.getStAtime());
    FileInfo->LastWriteTime = unix_to_filetime(attr.getStMtime());
    FileInfo->ChangeTime = unix_to_filetime(attr.getStMtime());
    FileInfo->IndexNumber = ctx->ino;
    FileInfo->HardLinks = attr.getStNlink();

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "GetFileInfo error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS SetBasicInfo(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    UINT32 FileAttributes,
    UINT64 CreationTime,
    UINT64 LastAccessTime,
    UINT64 LastWriteTime,
    UINT64 ChangeTime,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  // For now, we just return current file info
  return GetFileInfo(FileSystem, FileContext, FileInfo);
}

static NTSTATUS SetFileSize(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    UINT64 NewSize,
    BOOLEAN SetAllocationSize,
    FSP_FSCTL_FILE_INFO *FileInfo) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->setattrRequest();
    Setattr::Builder setattr = request.getReq();
    Setattr::FuseFileInfo::Builder fuseFileInfo = setattr.initFi();
    Setattr::Attr::Builder attr = setattr.initAttr();

    setattr.setIno(ctx->ino);
    setattr.setToSet(FUSE_SET_ATTR_SIZE);  // 8 = size
    attr.setStSize(NewSize);
    fillFileInfo(&fuseFileInfo, 0, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    return GetFileInfo(FileSystem, FileContext, FileInfo);
  } catch (const kj::Exception& e) {
    std::cerr << "SetFileSize error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static NTSTATUS CanDelete(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PWSTR FileName) {

  // Check if file/directory can be deleted
  // For now, we just return success - actual deletion will fail if not possible
  return STATUS_SUCCESS;
}

static NTSTATUS Rename(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PWSTR FileName,
    PWSTR NewFileName,
    BOOLEAN ReplaceIfExists) {

  std::string old_path = normalize_path(FileName);
  std::string new_path = normalize_path(NewFileName);

  // Get parent directories and names
  std::filesystem::path old_p(old_path);
  std::filesystem::path new_p(new_path);

  std::string old_parent_path = old_p.parent_path().string();
  std::string new_parent_path = new_p.parent_path().string();
  if (old_parent_path.empty()) old_parent_path = "/";
  if (new_parent_path.empty()) new_parent_path = "/";

  std::string old_name = old_p.filename().string();
  std::string new_name = new_p.filename().string();

  uint64_t old_parent_ino, new_parent_ino;
  uint32_t mode;
  uint64_t size;

  int err = lookup_path(old_parent_path, old_parent_ino, mode, size);
  if (err != 0) return errno_to_ntstatus(err);

  err = lookup_path(new_parent_path, new_parent_ino, mode, size);
  if (err != 0) return errno_to_ntstatus(err);

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->renameRequest();
    Rename::Builder rename = request.getReq();

    rename.setParent(old_parent_ino);
    rename.setName(old_name.c_str());
    rename.setNewparent(new_parent_ino);
    rename.setNewname(new_name.c_str());

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "Rename error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

static VOID Cleanup(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PWSTR FileName,
    ULONG Flags) {

  (void)FileSystem;
  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  if (Flags & FspCleanupDelete) {
    std::string path = normalize_path(FileName);
    std::filesystem::path p(path);
    std::string parent_path = p.parent_path().string();
    if (parent_path.empty()) parent_path = "/";
    std::string name = p.filename().string();

    uint64_t parent_ino;
    uint32_t mode;
    uint64_t size;
    int err = lookup_path(parent_path, parent_ino, mode, size);
    if (err != 0) return;

    try {
      auto& rpc = getRpc();
      auto& waitScope = rpc.ioContext->waitScope;
      auto& timer = rpc.getTimer();

      if (ctx->is_directory) {
        auto request = rpc.client->rmdirRequest();
        Rmdir::Builder rmdir = request.getReq();
        rmdir.setParent(parent_ino);
        rmdir.setName(name.c_str());
        waitWithTimeout(request.send(), timer, waitScope);
      } else {
        auto request = rpc.client->unlinkRequest();
        Unlink::Builder unlink = request.getReq();
        unlink.setParent(parent_ino);
        unlink.setName(name.c_str());
        waitWithTimeout(request.send(), timer, waitScope);
      }
    } catch (const kj::Exception& e) {
      std::cerr << "Cleanup delete error: " << e.getDescription().cStr() << std::endl;
    }
  }
}

static NTSTATUS ReadDirectory(
    FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID Buffer,
    ULONG BufferLength,
    PULONG PBytesTransferred) {

  GhostFSFileContext *ctx = (GhostFSFileContext *)FileContext;

  try {
    auto& rpc = getRpc();
    auto& waitScope = rpc.ioContext->waitScope;
    auto& timer = rpc.getTimer();

    auto request = rpc.client->readdirRequest();
    Readdir::Builder readdir = request.getReq();
    Readdir::FuseFileInfo::Builder fuseFileInfo = readdir.initFi();

    readdir.setIno(ctx->ino);
    readdir.setSize(BufferLength);
    readdir.setOff(0);
    fillFileInfo(&fuseFileInfo, O_RDONLY, ctx->fh);

    auto result = waitWithTimeout(request.send(), timer, waitScope);
    auto response = result.getRes();

    if (response.getRes() == -1) {
      return errno_to_ntstatus(response.getErrno());
    }

    PVOID DirBuffer = Buffer;
    BOOLEAN started = (Marker == nullptr);

    for (auto entry : response.getEntries()) {
      std::string entry_name = entry.getName().cStr();
      std::wstring wname = utf8_to_wstring(entry_name);

      // Skip . and ..
      if (entry_name == "." || entry_name == "..") continue;

      // Skip entries before marker
      if (!started) {
        if (wname == Marker) {
          started = true;
        }
        continue;
      }

      // Get entry attributes
      uint64_t entry_ino = entry.getIno();
      auto getattrRequest = rpc.client->getattrRequest();
      Getattr::Builder getattr = getattrRequest.getReq();
      Getattr::FuseFileInfo::Builder getattrFi = getattr.initFi();
      getattr.setIno(entry_ino);
      fillFileInfo(&getattrFi, 0, 0);

      auto getattrResult = waitWithTimeout(getattrRequest.send(), timer, waitScope);
      auto getattrResponse = getattrResult.getRes();

      FSP_FSCTL_DIR_INFO DirInfo;
      memset(&DirInfo, 0, sizeof(DirInfo));
      DirInfo.Size = sizeof(DirInfo);

      if (getattrResponse.getRes() == 0) {
        auto attr = getattrResponse.getAttr();
        DirInfo.FileInfo.FileAttributes = mode_to_attributes(attr.getStMode());
        DirInfo.FileInfo.FileSize = attr.getStSize();
        DirInfo.FileInfo.AllocationSize = (attr.getStSize() + 4095) & ~4095ULL;
        DirInfo.FileInfo.CreationTime = unix_to_filetime(attr.getStCtime());
        DirInfo.FileInfo.LastAccessTime = unix_to_filetime(attr.getStAtime());
        DirInfo.FileInfo.LastWriteTime = unix_to_filetime(attr.getStMtime());
        DirInfo.FileInfo.ChangeTime = unix_to_filetime(attr.getStMtime());
        DirInfo.FileInfo.IndexNumber = entry_ino;
        DirInfo.FileInfo.HardLinks = attr.getStNlink();
      } else {
        DirInfo.FileInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
      }

      BOOLEAN success = FspFileSystemAddDirInfo(&DirInfo, Buffer, BufferLength, PBytesTransferred);
      if (!success) {
        break;  // Buffer full
      }
    }

    FspFileSystemAddDirInfo(nullptr, Buffer, BufferLength, PBytesTransferred);

    return STATUS_SUCCESS;
  } catch (const kj::Exception& e) {
    std::cerr << "ReadDirectory error: " << e.getDescription().cStr() << std::endl;
    return STATUS_TIMEOUT;
  }
}

// WinFSP interface table
static FSP_FILE_SYSTEM_INTERFACE GhostFSInterface = {
  GetVolumeInfo,          // GetVolumeInfo
  nullptr,                // SetVolumeLabel
  GetSecurityByName,      // GetSecurityByName
  Create,                 // Create
  Open,                   // Open
  nullptr,                // Overwrite
  Cleanup,                // Cleanup
  Close,                  // Close
  Read,                   // Read
  Write,                  // Write
  Flush,                  // Flush
  GetFileInfo,            // GetFileInfo
  SetBasicInfo,           // SetBasicInfo
  SetFileSize,            // SetFileSize
  CanDelete,              // CanDelete
  Rename,                 // Rename
  nullptr,                // GetSecurity
  nullptr,                // SetSecurity
  ReadDirectory,          // ReadDirectory
};

// Global stop flag for dispatcher
static volatile LONG g_StopDispatcher = 0;

// Run file operation tests from within the client process
// This bypasses Windows session isolation issues in CI
static int run_internal_tests(const std::wstring& mount_root) {
  int passed = 0, failed = 0;

  auto test_pass = [&](const char* name) {
    std::cout << "[PASS] " << name << std::endl;
    passed++;
  };
  auto test_fail = [&](const char* name, DWORD err) {
    std::cout << "[FAIL] " << name << " (error " << err << ")" << std::endl;
    failed++;
  };

  std::wstring root = mount_root;
  if (root.back() != L'\\') root += L'\\';

  std::wcout << L"Test root: " << root << std::endl;

  // Check if drive is accessible
  DWORD attr = GetFileAttributesW(root.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES) {
    std::cout << "ERROR: Cannot access mount root (error " << GetLastError() << ")" << std::endl;
    std::cout << "Checking drive type..." << std::endl;
    UINT driveType = GetDriveTypeW(root.c_str());
    std::cout << "Drive type: " << driveType << " (0=unknown, 1=no_root, 2=removable, 3=fixed, 4=remote, 5=cdrom, 6=ramdisk)" << std::endl;
    return 1;
  }
  std::cout << "Mount root is accessible (attributes: " << attr << ")" << std::endl;

  // Test 1: Create file
  {
    std::wstring path = root + L"test1.txt";
    std::wcout << L"Creating: " << path << std::endl;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      const char* data = "hello world";
      DWORD written;
      WriteFile(h, data, (DWORD)strlen(data), &written, nullptr);
      CloseHandle(h);
      test_pass("Create file");
    } else {
      test_fail("Create file", GetLastError());
    }
  }

  // Test 2: Read file
  {
    std::wstring path = root + L"test1.txt";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      char buf[256] = {0};
      DWORD read;
      ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr);
      CloseHandle(h);
      if (strcmp(buf, "hello world") == 0) {
        test_pass("Read file");
      } else {
        std::cout << "[FAIL] Read file: content mismatch, got '" << buf << "'" << std::endl;
        failed++;
      }
    } else {
      test_fail("Read file", GetLastError());
    }
  }

  // Test 3: Create directory
  {
    std::wstring path = root + L"testdir";
    if (CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS) {
      DWORD attr = GetFileAttributesW(path.c_str());
      if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        test_pass("Create directory");
      } else {
        test_fail("Create directory (not a dir)", GetLastError());
      }
    } else {
      test_fail("Create directory", GetLastError());
    }
  }

  // Test 4: Write file in directory
  {
    std::wstring path = root + L"testdir\\nested.txt";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      const char* data = "nested content";
      DWORD written;
      WriteFile(h, data, (DWORD)strlen(data), &written, nullptr);
      CloseHandle(h);
      test_pass("Write file in directory");
    } else {
      test_fail("Write file in directory", GetLastError());
    }
  }

  // Test 5: List directory
  {
    std::wstring path = root + L"testdir\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(path.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
      int count = 0;
      do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
          count++;
        }
      } while (FindNextFileW(h, &fd));
      FindClose(h);
      if (count >= 1) {
        test_pass("List directory");
      } else {
        std::cout << "[FAIL] List directory: no files found" << std::endl;
        failed++;
      }
    } else {
      test_fail("List directory", GetLastError());
    }
  }

  // Test 6: Delete file
  {
    std::wstring path = root + L"test1.txt";
    if (DeleteFileW(path.c_str())) {
      if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        test_pass("Delete file");
      } else {
        std::cout << "[FAIL] Delete file: file still exists" << std::endl;
        failed++;
      }
    } else {
      test_fail("Delete file", GetLastError());
    }
  }

  // Test 7: Rename file
  {
    std::wstring src = root + L"testdir\\nested.txt";
    std::wstring dst = root + L"testdir\\renamed.txt";
    if (MoveFileW(src.c_str(), dst.c_str())) {
      if (GetFileAttributesW(dst.c_str()) != INVALID_FILE_ATTRIBUTES &&
          GetFileAttributesW(src.c_str()) == INVALID_FILE_ATTRIBUTES) {
        test_pass("Rename file");
      } else {
        std::cout << "[FAIL] Rename file: verification failed" << std::endl;
        failed++;
      }
    } else {
      test_fail("Rename file", GetLastError());
    }
  }

  // Test 8: Binary file (write and verify)
  {
    std::wstring path = root + L"binary.dat";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      unsigned char data[256];
      for (int i = 0; i < 256; i++) data[i] = (unsigned char)i;
      DWORD written;
      WriteFile(h, data, 256, &written, nullptr);
      CloseHandle(h);

      h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (h != INVALID_HANDLE_VALUE) {
        unsigned char buf[256];
        DWORD read;
        ReadFile(h, buf, 256, &read, nullptr);
        CloseHandle(h);
        if (read == 256 && memcmp(data, buf, 256) == 0) {
          test_pass("Binary file");
        } else {
          std::cout << "[FAIL] Binary file: content mismatch (read " << read << " bytes)" << std::endl;
          failed++;
        }
      } else {
        test_fail("Binary file read", GetLastError());
      }
    } else {
      test_fail("Binary file write", GetLastError());
    }
  }

  // Cleanup
  DeleteFileW((root + L"testdir\\renamed.txt").c_str());
  DeleteFileW((root + L"binary.dat").c_str());
  RemoveDirectoryW((root + L"testdir").c_str());

  std::cout << "\n==========================================" << std::endl;
  std::cout << "Passed: " << passed << std::endl;
  std::cout << "Failed: " << failed << std::endl;
  std::cout << "==========================================" << std::endl;

  return failed > 0 ? 1 : 0;
}

int start_fs_windows(const wchar_t* mountpoint, std::string host, int port,
                     std::string user, std::string token,
                     uint8_t write_back_cache_size, uint8_t read_ahead_cache_size,
                     std::string cert_file, bool test_mode) {

  // Initialize connection
  if (!init_connection(host, port, user, token, cert_file, write_back_cache_size, read_ahead_cache_size)) {
    return 1;
  }

  // Create WinFSP filesystem
  FSP_FSCTL_VOLUME_PARAMS VolumeParams;
  memset(&VolumeParams, 0, sizeof(VolumeParams));
  VolumeParams.SectorSize = 4096;
  VolumeParams.SectorsPerAllocationUnit = 1;
  VolumeParams.VolumeCreationTime = 0;
  VolumeParams.VolumeSerialNumber = 0;
  VolumeParams.FileInfoTimeout = 1000;
  VolumeParams.CaseSensitiveSearch = 0;
  VolumeParams.CasePreservedNames = 1;
  VolumeParams.UnicodeOnDisk = 1;
  VolumeParams.PersistentAcls = 1;  // Changed: needed for proper security handling
  VolumeParams.PostCleanupWhenModifiedOnly = 1;
  VolumeParams.PassQueryDirectoryPattern = 1;  // Changed: pass pattern to ReadDirectory
  VolumeParams.FlushAndPurgeOnCleanup = 1;  // Added: flush on cleanup
  VolumeParams.UmFileContextIsUserContext2 = 1;  // Added: we manage file context
  wcscpy_s(VolumeParams.Prefix, sizeof(VolumeParams.Prefix) / sizeof(WCHAR), L"");
  wcscpy_s(VolumeParams.FileSystemName, sizeof(VolumeParams.FileSystemName) / sizeof(WCHAR), L"GhostFS");

  std::cout << "Creating WinFSP filesystem with device: " << FSP_FSCTL_DISK_DEVICE_NAME << std::endl;

  NTSTATUS Result = FspFileSystemCreate(
    const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME),
    &VolumeParams,
    &GhostFSInterface,
    &g_FileSystem);

  std::cout << "FspFileSystemCreate result: 0x" << std::hex << Result << std::dec << std::endl;

  if (!NT_SUCCESS(Result)) {
    std::cerr << "Failed to create WinFSP filesystem: 0x" << std::hex << Result << std::dec << std::endl;
    return 1;
  }

  // Enable debug logging
  FspFileSystemSetDebugLog(g_FileSystem, (UINT32)-1);
  std::cout << "Debug logging enabled" << std::endl;

  std::wcout << L"Setting mount point: " << mountpoint << std::endl;
  Result = FspFileSystemSetMountPoint(g_FileSystem, const_cast<PWSTR>(mountpoint));
  std::cout << "FspFileSystemSetMountPoint result: 0x" << std::hex << Result << std::dec << std::endl;

  if (!NT_SUCCESS(Result)) {
    std::cerr << "Failed to set mount point: 0x" << std::hex << Result << std::dec << std::endl;
    FspFileSystemDelete(g_FileSystem);
    return 1;
  }

  std::cout << "Starting dispatcher..." << std::endl;
  Result = FspFileSystemStartDispatcher(g_FileSystem, 0);
  std::cout << "FspFileSystemStartDispatcher result: 0x" << std::hex << Result << std::dec << std::endl;

  if (!NT_SUCCESS(Result)) {
    std::cerr << "Failed to start WinFSP dispatcher: 0x" << std::hex << Result << std::dec << std::endl;
    FspFileSystemDelete(g_FileSystem);
    return 1;
  }

  std::wcout << L"Mounted GhostFS at " << mountpoint << std::endl;

  // Verify the mount is working by checking file system info
  std::wcout << L"Verifying mount..." << std::endl;
  std::wcout << L"FileSystem pointer: " << g_FileSystem << std::endl;
  if (g_FileSystem) {
    std::wcout << L"MountPoint: " << (FspFileSystemMountPoint(g_FileSystem) ? FspFileSystemMountPoint(g_FileSystem) : L"(null)") << std::endl;
  }

  // If test mode, run internal tests and exit
  if (test_mode) {
    std::cout << "Running internal file operation tests..." << std::endl;
    std::cout << "Waiting for filesystem to stabilize..." << std::endl;
    Sleep(3000); // Give filesystem more time to stabilize

    // Verify drive exists before testing
    std::wstring driveRoot = std::wstring(mountpoint);
    if (driveRoot.back() != L'\\') driveRoot += L'\\';

    DWORD driveType = GetDriveTypeW(driveRoot.c_str());
    std::wcout << L"Drive type for " << driveRoot << L": " << driveType << std::endl;
    std::cout << "(0=unknown, 1=no_root, 2=removable, 3=fixed, 4=remote, 5=cdrom, 6=ramdisk)" << std::endl;

    // Try a simple test directly from main thread first
    std::cout << "Testing GetFileAttributesW from main thread..." << std::endl;
    DWORD attr = GetFileAttributesW(driveRoot.c_str());
    std::cout << "Result: " << attr << " (error: " << GetLastError() << ")" << std::endl;

    // Also try opening a handle directly
    std::cout << "Testing CreateFileW on root..." << std::endl;
    HANDLE hRoot = CreateFileW(
        driveRoot.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // Needed for directories
        nullptr);
    if (hRoot != INVALID_HANDLE_VALUE) {
      std::cout << "Root handle opened successfully!" << std::endl;
      CloseHandle(hRoot);
    } else {
      std::cout << "Failed to open root (error: " << GetLastError() << ")" << std::endl;
    }

    // Run tests in a separate thread to avoid blocking dispatcher
    std::wstring mp(mountpoint);
    int test_result = 1;
    std::thread test_thread([&mp, &test_result]() {
      Sleep(500); // Extra delay for thread safety
      test_result = run_internal_tests(mp);
    });
    test_thread.join();

    FspFileSystemStopDispatcher(g_FileSystem);
    FspFileSystemDelete(g_FileSystem);
    return test_result;
  }

  std::cout << "Press Ctrl+C to unmount..." << std::endl;

  // Reset stop flag
  InterlockedExchange(&g_StopDispatcher, 0);

  // Wait for termination signal
  SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
      InterlockedExchange(&g_StopDispatcher, 1);
      if (g_FileSystem) {
        FspFileSystemStopDispatcher(g_FileSystem);
      }
      return TRUE;
    }
    return FALSE;
  }, TRUE);

  // Wait until stop signal
  while (InterlockedCompareExchange(&g_StopDispatcher, 0, 0) == 0) {
    Sleep(1000);
  }

  std::cout << "Unmounting GhostFS..." << std::endl;
  FspFileSystemDelete(g_FileSystem);
  std::cout << "GhostFS unmounted." << std::endl;

  return 0;
}

#endif // _WIN32
