#pragma once

#include <string>

namespace ghostfs {
namespace csi {

// Start the CSI gRPC server
// socket_path: Unix domain socket path (e.g., /csi/csi.sock)
// Returns 0 on success, non-zero on failure
int start_csi_server(const std::string& socket_path);

}  // namespace csi
}  // namespace ghostfs
