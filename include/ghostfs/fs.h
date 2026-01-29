#define FUSE_USE_VERSION 29
#define _FILE_OFFSET_BITS 64

#include <fuse_lowlevel.h>

#include <atomic>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

int start_fs(char* executable, char* argmnt, std::vector<std::string> options, std::string host,
             int port, std::string user, std::string token, uint8_t write_back_cache_size,
             uint8_t read_ahead_cache_size, std::string cert_file, bool use_tls = false);

int ghostfs_stat(fuse_ino_t ino, int64_t fh, struct stat* stbuf);
int ghostfs_stat(fuse_ino_t ino, struct stat* stbuf);

// Thread-safe inode map management
extern std::unordered_map<uint64_t, std::string> ino_to_path;
extern std::unordered_map<std::string, uint64_t> path_to_ino;
extern std::atomic<uint64_t> current_ino;
extern std::shared_mutex g_inode_mutex;

// Thread-safe helper functions for inode management
std::string get_path_for_ino(uint64_t ino);
uint64_t get_ino_for_path(const std::string& path);
uint64_t assign_inode(const std::string& path);
bool has_inode(uint64_t ino);
bool has_path(const std::string& path);
void remove_inode(uint64_t ino);
void update_inode_path(uint64_t ino, const std::string& old_path, const std::string& new_path);

struct dirbuf {
  char* p;
  size_t size;
};

void dirbuf_add(fuse_req_t req, struct dirbuf* b, const char* name, fuse_ino_t ino);

uint64_t get_parent_ino(uint64_t ino, std::string path);

// Encryption support
void set_encryption_enabled(bool enabled);
bool is_encryption_enabled();
bool load_encryption_key(const std::string& key_path);
