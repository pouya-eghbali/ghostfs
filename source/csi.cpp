#ifdef GHOSTFS_CSI_SUPPORT

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "csi.grpc.pb.h"
#include <ghostfs/fs.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;

namespace ghostfs {
namespace csi {

// Track active mounts: target_path -> thread
static std::map<std::string, std::thread> active_mounts;
static std::mutex mounts_mutex;

// Check if path is a mountpoint
static bool is_mountpoint(const std::string& path) {
    struct stat st_path, st_parent;
    std::string parent = path + "/..";

    if (stat(path.c_str(), &st_path) != 0) return false;
    if (stat(parent.c_str(), &st_parent) != 0) return false;

    return st_path.st_dev != st_parent.st_dev;
}

// Wait for mount to appear
static bool wait_for_mount(const std::string& path, int timeout_ms = 10000) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        if (is_mountpoint(path)) return true;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) return false;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Identity Service Implementation
class IdentityServiceImpl final : public ::csi::v1::Identity::Service {
public:
    Status GetPluginInfo(ServerContext* context,
                         const ::csi::v1::GetPluginInfoRequest* request,
                         ::csi::v1::GetPluginInfoResponse* response) override {
        response->set_name("ghostfs.csi.k8s.io");
        response->set_vendor_version("1.0.0");
        return Status::OK;
    }

    Status GetPluginCapabilities(ServerContext* context,
                                  const ::csi::v1::GetPluginCapabilitiesRequest* request,
                                  ::csi::v1::GetPluginCapabilitiesResponse* response) override {
        // We only support Node service, no Controller
        return Status::OK;
    }

    Status Probe(ServerContext* context,
                 const ::csi::v1::ProbeRequest* request,
                 ::csi::v1::ProbeResponse* response) override {
        response->mutable_ready()->set_value(true);
        return Status::OK;
    }
};

// Node Service Implementation
class NodeServiceImpl final : public ::csi::v1::Node::Service {
    std::string node_id_;

public:
    NodeServiceImpl() {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        node_id_ = hostname;
    }

    Status NodePublishVolume(ServerContext* context,
                             const ::csi::v1::NodePublishVolumeRequest* request,
                             ::csi::v1::NodePublishVolumeResponse* response) override {

        const std::string& volume_id = request->volume_id();
        const std::string& target_path = request->target_path();
        const auto& vol_ctx = request->volume_context();

        // Extract connection parameters from volume context
        std::string host = "127.0.0.1";
        std::string user, token, cert;
        int port = 3444;
        uint8_t write_back = 8, read_ahead = 8;

        if (vol_ctx.count("host")) host = vol_ctx.at("host");
        if (vol_ctx.count("port")) port = std::stoi(vol_ctx.at("port"));
        if (vol_ctx.count("user")) user = vol_ctx.at("user");
        if (vol_ctx.count("token")) token = vol_ctx.at("token");
        if (vol_ctx.count("cert")) cert = vol_ctx.at("cert");
        if (vol_ctx.count("writeBack")) write_back = std::stoi(vol_ctx.at("writeBack"));
        if (vol_ctx.count("readAhead")) read_ahead = std::stoi(vol_ctx.at("readAhead"));

        if (user.empty()) {
            return Status(StatusCode::INVALID_ARGUMENT, "user is required in volume context");
        }
        if (token.empty()) {
            return Status(StatusCode::INVALID_ARGUMENT, "token is required in volume context");
        }

        // Create target directory if it doesn't exist
        mkdir(target_path.c_str(), 0755);

        // Check if already mounted
        if (is_mountpoint(target_path)) {
            std::cout << "CSI: " << target_path << " already mounted" << std::endl;
            return Status::OK;
        }

        std::cout << "CSI: Mounting GhostFS at " << target_path << std::endl;
        std::cout << "CSI: host=" << host << " port=" << port << " user=" << user << std::endl;

        // Start mount in background thread
        std::thread mount_thread([=]() {
            char* target = strdup(target_path.c_str());
            std::vector<std::string> options;

            // Allow other users to access the mount (needed for containers)
            options.push_back("allow_other");

            int result = start_fs(
                (char*)"ghostfs",  // executable name (not used)
                target,
                options,
                host,
                port,
                user,
                token,
                write_back,
                read_ahead,
                cert
            );

            free(target);

            if (result != 0) {
                std::cerr << "CSI: Mount failed with code " << result << std::endl;
            }
        });

        // Wait for mount to appear
        if (!wait_for_mount(target_path)) {
            mount_thread.detach();
            return Status(StatusCode::INTERNAL, "Mount timeout - GhostFS failed to mount");
        }

        // Store thread handle
        {
            std::lock_guard<std::mutex> lock(mounts_mutex);
            active_mounts[target_path] = std::move(mount_thread);
        }

        std::cout << "CSI: Successfully mounted at " << target_path << std::endl;
        return Status::OK;
    }

    Status NodeUnpublishVolume(ServerContext* context,
                               const ::csi::v1::NodeUnpublishVolumeRequest* request,
                               ::csi::v1::NodeUnpublishVolumeResponse* response) override {

        const std::string& target_path = request->target_path();

        std::cout << "CSI: Unmounting " << target_path << std::endl;

        if (!is_mountpoint(target_path)) {
            std::cout << "CSI: " << target_path << " not mounted" << std::endl;
            return Status::OK;
        }

        // Unmount
#ifdef __linux__
        int ret = umount2(target_path.c_str(), MNT_DETACH);
#else
        int ret = unmount(target_path.c_str(), MNT_FORCE);
#endif

        if (ret != 0) {
            std::cerr << "CSI: Unmount failed: " << strerror(errno) << std::endl;
            return Status(StatusCode::INTERNAL, "Unmount failed: " + std::string(strerror(errno)));
        }

        // Clean up thread
        {
            std::lock_guard<std::mutex> lock(mounts_mutex);
            auto it = active_mounts.find(target_path);
            if (it != active_mounts.end()) {
                if (it->second.joinable()) {
                    it->second.detach();
                }
                active_mounts.erase(it);
            }
        }

        std::cout << "CSI: Successfully unmounted " << target_path << std::endl;
        return Status::OK;
    }

    Status NodeGetCapabilities(ServerContext* context,
                               const ::csi::v1::NodeGetCapabilitiesRequest* request,
                               ::csi::v1::NodeGetCapabilitiesResponse* response) override {
        // No special capabilities needed for basic FUSE mount
        return Status::OK;
    }

    Status NodeGetInfo(ServerContext* context,
                       const ::csi::v1::NodeGetInfoRequest* request,
                       ::csi::v1::NodeGetInfoResponse* response) override {
        response->set_node_id(node_id_);
        return Status::OK;
    }

    // Stub implementations for other required methods
    Status NodeStageVolume(ServerContext* context,
                           const ::csi::v1::NodeStageVolumeRequest* request,
                           ::csi::v1::NodeStageVolumeResponse* response) override {
        return Status(StatusCode::UNIMPLEMENTED, "NodeStageVolume not supported");
    }

    Status NodeUnstageVolume(ServerContext* context,
                             const ::csi::v1::NodeUnstageVolumeRequest* request,
                             ::csi::v1::NodeUnstageVolumeResponse* response) override {
        return Status(StatusCode::UNIMPLEMENTED, "NodeUnstageVolume not supported");
    }

    Status NodeGetVolumeStats(ServerContext* context,
                              const ::csi::v1::NodeGetVolumeStatsRequest* request,
                              ::csi::v1::NodeGetVolumeStatsResponse* response) override {
        return Status(StatusCode::UNIMPLEMENTED, "NodeGetVolumeStats not supported");
    }

    Status NodeExpandVolume(ServerContext* context,
                            const ::csi::v1::NodeExpandVolumeRequest* request,
                            ::csi::v1::NodeExpandVolumeResponse* response) override {
        return Status(StatusCode::UNIMPLEMENTED, "NodeExpandVolume not supported");
    }
};

// Start CSI gRPC server
int start_csi_server(const std::string& socket_path) {
    // Remove existing socket
    unlink(socket_path.c_str());

    std::string server_address = "unix://" + socket_path;

    IdentityServiceImpl identity_service;
    NodeServiceImpl node_service;

    grpc::EnableDefaultHealthCheckService(true);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&identity_service);
    builder.RegisterService(&node_service);

    std::unique_ptr<Server> server(builder.BuildAndStart());

    if (!server) {
        std::cerr << "Failed to start CSI server on " << server_address << std::endl;
        return 1;
    }

    std::cout << "CSI server listening on " << server_address << std::endl;
    server->Wait();

    return 0;
}

}  // namespace csi
}  // namespace ghostfs

#endif  // GHOSTFS_CSI_SUPPORT
