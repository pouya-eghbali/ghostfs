#include <ghostfs/fs.h>
#include <ghostfs/ghostfs.h>
#include <ghostfs/rpc.h>
#include <ghostfs/version.h>
#include <sys/resource.h>

#ifdef GHOSTFS_CSI_SUPPORT
#include <ghostfs/csi.h>
#endif

#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>

auto main(int argc, char** argv) -> int {
  cxxopts::Options options("GhostFS", "One Ghosty FS");

  std::string default_root = std::filesystem::path(getenv("HOME")) / ".ghostfs" / "root";

  // clang-format off
  options.add_options()
    ("h,help", "Show help")
    ("v,version", "Print the current version number")
    ("b,bind", "Bind IP address", cxxopts::value<std::string>()->default_value("127.0.0.1"))
    ("H,host", "Capnp host address", cxxopts::value<std::string>()->default_value("127.0.0.1"))
    ("p,port", "Server port", cxxopts::value<uint16_t>()->default_value("3444"))
    ("P,auth-port", "Server auth port", cxxopts::value<uint16_t>()->default_value("3445"))
    ("r,root", "Root directory", cxxopts::value<std::string>()->default_value(default_root))
    ("S,suffix", "User data subdirectory suffix", cxxopts::value<std::string>()->default_value(""))
    ("F,source", "Soft mount source directory", cxxopts::value<std::string>()->default_value(""))
    ("d,destination", "Soft mount destination directory", cxxopts::value<std::string>()->default_value(""))
    ("o,options", "Fuse mount options", cxxopts::value<std::vector<std::string>>())
    ("u,user", "Username (GhostFS subdirectory)", cxxopts::value<std::string>())
    ("t,token", "Authentication token", cxxopts::value<std::string>()->default_value(""))
    ("R,retries", "Authentication token retries", cxxopts::value<int64_t>()->default_value("-1"))
    ("w,write-back", "Write back cache size", cxxopts::value<uint8_t>()->default_value("8"))
    ("C,read-ahead", "Read ahead cache size", cxxopts::value<uint8_t>()->default_value("8"))
    ("k,key", "TLS key", cxxopts::value<std::string>()->default_value(""))
    ("T,cert", "TLS cert", cxxopts::value<std::string>()->default_value(""))
    ("A,authorize", "Run in authorizer mode")
    ("m,mount", "Soft mount a directory")
    ("M,mounts", "Get all soft mounts for user")
    ("U,unmount", "Soft unmount a directory")
    ("s,server", "Run in server mode")
    ("c,client", "Run in client mode")
#ifdef GHOSTFS_CSI_SUPPORT
    ("csi", "Run as CSI driver")
    ("csi-socket", "CSI socket path", cxxopts::value<std::string>()->default_value("/csi/csi.sock"))
#endif
    ("mountpoint", "Mount point for client mode", cxxopts::value<std::string>()->default_value(""));

  // clang-format on

  options.parse_positional({"mountpoint"});
  auto result = options.parse(argc, argv);

  // std::cout << "UUID: " << gen_uuid() << std::endl;

  if (result["help"].as<bool>()) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  if (result["version"].as<bool>()) {
    std::cout << "GhostFS, version " << GHOSTFS_VERSION << std::endl;
    return 0;
  }

  if (result["server"].as<bool>()) {
    // Increse stack size

    const rlim_t min_stack_size = 64 * 1024 * 1024;
    struct rlimit rl;

    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
      if (rl.rlim_cur < min_stack_size) {
        rl.rlim_cur = min_stack_size;
        setrlimit(RLIMIT_STACK, &rl);
      }
    }

    std::string root = result["root"].as<std::string>();
    std::string bind = result["bind"].as<std::string>();
    std::string suffix = result["suffix"].as<std::string>();
    std::string key = result["key"].as<std::string>();
    std::string cert = result["cert"].as<std::string>();

    uint16_t port = result["port"].as<uint16_t>();
    uint16_t auth_port = result["auth-port"].as<uint16_t>();

    return start_rpc_server(bind, port, auth_port, root, suffix, key, cert);

  } else if (result["client"].as<bool>()) {
    std::string host = result["host"].as<std::string>();
    uint16_t port = result["port"].as<uint16_t>();
    std::string user = result["user"].as<std::string>();
    std::string token = result["token"].as<std::string>();
    std::string cert = result["cert"].as<std::string>();
    std::string mountpoint = result["mountpoint"].as<std::string>();
    std::vector<std::string> fuse_options;
    if (result.count("options")) {
      fuse_options = result["options"].as<std::vector<std::string>>();
    }
    int64_t write_back = result["write-back"].as<uint8_t>();
    int64_t read_ahead = result["read-ahead"].as<uint8_t>();

    if (mountpoint.empty()) {
      std::cerr << "Error: mountpoint is required for client mode" << std::endl;
      return 1;
    }

    char* mountpoint_arg = const_cast<char*>(mountpoint.c_str());
    return start_fs(argv[0], mountpoint_arg, fuse_options, host, port, user, token, write_back,
                    read_ahead, cert);

  } else if (result["authorize"].as<bool>()) {
    uint16_t port = result["auth-port"].as<uint16_t>();
    std::string user = result["user"].as<std::string>();
    std::string token = result["token"].as<std::string>();
    int64_t retries = result["retries"].as<int64_t>();

    return rpc_add_token(port, user, token, retries);

  } else if (result["mount"].as<bool>()) {
    uint16_t port = result["auth-port"].as<uint16_t>();
    std::string user = result["user"].as<std::string>();
    std::string source = result["source"].as<std::string>();
    std::string destination = result["destination"].as<std::string>();

    return rpc_mount(port, user, source, destination);

  } else if (result["mounts"].as<bool>()) {
    uint16_t port = result["auth-port"].as<uint16_t>();
    std::string user = result["user"].as<std::string>();

    return rpc_print_mounts(port, user);

  } else if (result["unmount"].as<bool>()) {
    uint16_t port = result["auth-port"].as<uint16_t>();
    std::string user = result["user"].as<std::string>();
    std::string destination = result["destination"].as<std::string>();

    return destination.length() ? rpc_unmount(port, user, destination)
                                : rpc_unmount_all(port, user);

#ifdef GHOSTFS_CSI_SUPPORT
  } else if (result["csi"].as<bool>()) {
    std::string socket_path = result["csi-socket"].as<std::string>();
    std::cout << "Starting GhostFS CSI driver..." << std::endl;
    return ghostfs::csi::start_csi_server(socket_path);
#endif
  }

  // No mode specified - show help
  std::cout << options.help() << std::endl;
  return 1;
}
