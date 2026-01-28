#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ghostfs::http {

// Callback type for ACME challenge responses
// Takes a challenge token, returns the key authorization response (or empty string if not found)
using AcmeChallengeCallback = std::function<std::string(const std::string& token)>;

// Set the ACME challenge callback
// This allows the cert manager to provide challenge responses
void set_acme_challenge_callback(AcmeChallengeCallback callback);

// Start the HTTP server for the web UI
// Parameters:
//   bind - Address to bind to (e.g., "0.0.0.0" or "127.0.0.1")
//   http_port - Port for HTTP server
//   rpc_port - Port for the Cap'n Proto RPC server
//   auth_port - Port for the auth RPC server
//   root - Root directory for the filesystem
//   suffix - User data subdirectory suffix
//   key_file - TLS key file path (empty for no TLS)
//   cert_file - TLS certificate file path (empty for no TLS)
//   static_dir - Directory containing static web files (empty for API-only)
//   skip_auth_server - If true, don't start the auth RPC server (use when running with --server)
// Returns 0 on success, non-zero on error
int start_http_server(const std::string& bind, uint16_t http_port, uint16_t rpc_port,
                      uint16_t auth_port, const std::string& root, const std::string& suffix,
                      const std::string& key_file, const std::string& cert_file,
                      const std::string& static_dir, bool skip_auth_server = false);

}  // namespace ghostfs::http
