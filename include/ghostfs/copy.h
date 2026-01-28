#pragma once

#include <cstdint>
#include <string>

namespace ghostfs {

  struct CopyConfig {
    std::string source;
    std::string destination;
    std::string host;
    uint16_t port;
    std::string user;
    std::string token;
    std::string cert;
    bool encrypt = false;
    std::string encryption_key;
    bool show_progress = false;
  };

  int run_copy(const CopyConfig& config);

}  // namespace ghostfs
