#define FUSE_USE_VERSION 29
#define _FILE_OFFSET_BITS 64

#include <fuse_lowlevel.h>

#include <map>
#include <string>
#include <vector>

int start_fs(char* executable, char* argmnt, std::vector<std::string> options, std::string host,
             int port, std::string user, std::string token, uint8_t write_back_cache_size,
             uint8_t read_ahead_cache_size, std::string cert_file);

int ghostfs_stat(fuse_ino_t ino, int64_t fh, struct stat* stbuf);
int ghostfs_stat(fuse_ino_t ino, struct stat* stbuf);

extern std::map<uint64_t, std::string> ino_to_path;
extern std::map<std::string, uint64_t> path_to_ino;
extern uint64_t current_ino;

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
