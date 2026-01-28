#include <ghostfs/acme.h>
#include <ghostfs/benchmark.h>
#include <ghostfs/cert_manager.h>
#include <ghostfs/copy.h>
#include <ghostfs/crypto.h>
#include <ghostfs/fs.h>
#include <ghostfs/ghostfs.h>
#include <ghostfs/http.h>
#include <ghostfs/rpc.h>
#include <ghostfs/version.h>
#include <sys/resource.h>

#ifdef GHOSTFS_CSI_SUPPORT
#  include <ghostfs/csi.h>
#endif

#include <chrono>
#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
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
    ("B,benchmark", "Run filesystem benchmark")
    ("D,dir", "Benchmark directory", cxxopts::value<std::string>()->default_value(""))
    ("small-files", "Number of small files for benchmark", cxxopts::value<uint32_t>()->default_value("1000"))
    ("small-size", "Size of small files in bytes", cxxopts::value<uint32_t>()->default_value("4096"))
    ("large-size", "Size of large file in MB", cxxopts::value<uint32_t>()->default_value("1000"))
    ("jobs", "Parallel jobs for benchmark", cxxopts::value<uint8_t>()->default_value("8"))
    ("no-verify", "Skip integrity verification")
    ("e,encrypt", "Enable client-side encryption")
    ("encryption-key", "Path to encryption key file", cxxopts::value<std::string>()->default_value(""))
    ("generate-key", "Generate a new encryption key file", cxxopts::value<std::string>())
    ("progress", "Show progress bar for copy operations")
    ("W,http", "Enable HTTP web server")
    ("http-port", "HTTP server port", cxxopts::value<uint16_t>()->default_value("8080"))
    ("http-static", "Static files directory for web UI", cxxopts::value<std::string>()->default_value(""))
    ("acme", "Enable automatic Let's Encrypt certificates")
    ("acme-domain", "Domain name for ACME certificate", cxxopts::value<std::string>()->default_value(""))
    ("acme-email", "Email for Let's Encrypt registration", cxxopts::value<std::string>()->default_value(""))
    ("acme-staging", "Use Let's Encrypt staging environment (for testing)")
    ("acme-cert-dir", "Certificate storage directory", cxxopts::value<std::string>()->default_value(""))
    ("acme-challenge-port", "HTTP-01 challenge port", cxxopts::value<uint16_t>()->default_value("80"))
#ifdef GHOSTFS_CSI_SUPPORT
    ("csi", "Run as CSI driver")
    ("csi-socket", "CSI socket path", cxxopts::value<std::string>()->default_value("/csi/csi.sock"))
#endif
    ("mountpoint", "Mount point for client mode or copy destination", cxxopts::value<std::string>()->default_value(""))
    ("cp-source", "Copy source path (for cp command)", cxxopts::value<std::string>()->default_value(""));

  // clang-format on

  // Check for cp command: GhostFS cp <source> <destination> [options]
  bool is_copy_mode = (argc >= 2 && std::string(argv[1]) == "cp");

  // Keep modified_argv alive for the duration of the program
  std::vector<char*> modified_argv;

  if (is_copy_mode) {
    // For cp mode, skip the "cp" argument in parsing
    // Create a modified argv that removes "cp" from position 1
    modified_argv.push_back(argv[0]);
    for (int i = 2; i < argc; ++i) {
      modified_argv.push_back(argv[i]);
    }
    options.parse_positional({"cp-source", "mountpoint"});
    argc = static_cast<int>(modified_argv.size());
    argv = modified_argv.data();
  } else {
    options.parse_positional({"mountpoint"});
  }

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

  // Key generation command
  if (result.count("generate-key")) {
    if (!ghostfs::crypto::init()) {
      std::cerr << "Failed to initialize encryption" << std::endl;
      return 1;
    }
    std::string key_path = result["generate-key"].as<std::string>();
    if (ghostfs::crypto::generate_key_file(key_path)) {
      std::cout << "Encryption key generated: " << key_path << std::endl;
      return 0;
    } else {
      std::cerr << "Failed to generate encryption key" << std::endl;
      return 1;
    }
  }

  bool run_http = result["http"].as<bool>();
  bool run_server = result["server"].as<bool>();

  // ACME configuration
  bool use_acme = result["acme"].as<bool>();
  std::string acme_domain = result["acme-domain"].as<std::string>();
  std::string acme_email = result["acme-email"].as<std::string>();
  bool acme_staging = result["acme-staging"].as<bool>();
  std::string acme_cert_dir = result["acme-cert-dir"].as<std::string>();
  uint16_t acme_challenge_port = result["acme-challenge-port"].as<uint16_t>();

  // Validate ACME options
  if (use_acme && (acme_domain.empty() || acme_email.empty())) {
    std::cerr << "Error: --acme requires --acme-domain and --acme-email" << std::endl;
    return 1;
  }

  // Certificate manager (initialized if ACME is enabled)
  std::unique_ptr<ghostfs::acme::CertManager> cert_manager;

  if (run_http && run_server) {
    // Combined mode: Run both RPC server and HTTP web server
    std::string root = result["root"].as<std::string>();
    std::string bind = result["bind"].as<std::string>();
    std::string suffix = result["suffix"].as<std::string>();
    std::string key = result["key"].as<std::string>();
    std::string cert = result["cert"].as<std::string>();
    std::string static_dir = result["http-static"].as<std::string>();

    uint16_t port = result["port"].as<uint16_t>();
    uint16_t auth_port = result["auth-port"].as<uint16_t>();
    uint16_t http_port = result["http-port"].as<uint16_t>();

    // Initialize crypto if needed
    if (!ghostfs::crypto::init()) {
      std::cerr << "Warning: Failed to initialize encryption support" << std::endl;
    }

    // Initialize ACME if enabled
    if (use_acme) {
      ghostfs::acme::AcmeConfig acme_config;
      acme_config.domain = acme_domain;
      acme_config.email = acme_email;
      acme_config.staging = acme_staging;
      acme_config.cert_dir = acme_cert_dir.empty() ? ghostfs::acme::get_default_cert_dir() : acme_cert_dir;
      acme_config.challenge_port = acme_challenge_port;

      cert_manager = std::make_unique<ghostfs::acme::CertManager>(acme_config);

      // Set up challenge callback for HTTP server
      ghostfs::http::set_acme_challenge_callback([&cert_manager](const std::string& token) {
        return cert_manager->get_challenge_response(token);
      });

      if (!cert_manager->init()) {
        std::cerr << "Error: Failed to initialize ACME certificate manager" << std::endl;
        return 1;
      }

      // Get certificate paths
      auto [cert_path, key_path] = cert_manager->get_cert_paths();
      if (!cert_path.empty() && !key_path.empty()) {
        cert = cert_path;
        key = key_path;
        std::cout << "Using ACME certificate: " << cert_path << std::endl;
      }

      // Start background renewal
      cert_manager->start_renewal_loop();
    }

    // Increase stack size for RPC server
    const rlim_t min_stack_size = 64 * 1024 * 1024;
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
      if (rl.rlim_cur < min_stack_size) {
        rl.rlim_cur = min_stack_size;
        setrlimit(RLIMIT_STACK, &rl);
      }
    }

    // Start RPC server in background thread
    start_rpc_server_async(bind, port, auth_port, root, suffix, key, cert);

    // Give RPC server time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "Starting HTTP web server on port " << http_port << "..." << std::endl;

    // Start HTTP server in main thread (this blocks)
    // Note: HTTP server uses its own auth mechanism, but RPC is available for FUSE clients
    // Skip auth server since the RPC server already started one
    return ghostfs::http::start_http_server(bind, http_port, port, auth_port, root, suffix, key,
                                            cert, static_dir, true);

  } else if (run_http) {
    // HTTP web server mode only
    std::string root = result["root"].as<std::string>();
    std::string bind = result["bind"].as<std::string>();
    std::string suffix = result["suffix"].as<std::string>();
    std::string key = result["key"].as<std::string>();
    std::string cert = result["cert"].as<std::string>();
    std::string static_dir = result["http-static"].as<std::string>();

    uint16_t port = result["port"].as<uint16_t>();
    uint16_t auth_port = result["auth-port"].as<uint16_t>();
    uint16_t http_port = result["http-port"].as<uint16_t>();

    // Initialize crypto if needed
    if (!ghostfs::crypto::init()) {
      std::cerr << "Warning: Failed to initialize encryption support" << std::endl;
    }

    // Initialize ACME if enabled
    if (use_acme) {
      ghostfs::acme::AcmeConfig acme_config;
      acme_config.domain = acme_domain;
      acme_config.email = acme_email;
      acme_config.staging = acme_staging;
      acme_config.cert_dir = acme_cert_dir.empty() ? ghostfs::acme::get_default_cert_dir() : acme_cert_dir;
      acme_config.challenge_port = acme_challenge_port;

      cert_manager = std::make_unique<ghostfs::acme::CertManager>(acme_config);

      // Set up challenge callback for HTTP server
      ghostfs::http::set_acme_challenge_callback([&cert_manager](const std::string& token) {
        return cert_manager->get_challenge_response(token);
      });

      if (!cert_manager->init()) {
        std::cerr << "Error: Failed to initialize ACME certificate manager" << std::endl;
        return 1;
      }

      // Get certificate paths
      auto [cert_path, key_path] = cert_manager->get_cert_paths();
      if (!cert_path.empty() && !key_path.empty()) {
        cert = cert_path;
        key = key_path;
        std::cout << "Using ACME certificate: " << cert_path << std::endl;
      }

      // Start background renewal
      cert_manager->start_renewal_loop();
    }

    return ghostfs::http::start_http_server(bind, http_port, port, auth_port, root, suffix, key,
                                            cert, static_dir);

  } else if (run_server) {
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

    // Handle encryption
    bool encrypt = result["encrypt"].as<bool>();
    std::string encryption_key = result["encryption-key"].as<std::string>();

    if (encrypt) {
      if (encryption_key.empty()) {
        std::cerr << "Error: --encrypt requires --encryption-key" << std::endl;
        return 1;
      }
      if (!ghostfs::crypto::init()) {
        std::cerr << "Failed to initialize encryption" << std::endl;
        return 1;
      }
      if (!load_encryption_key(encryption_key)) {
        std::cerr << "Failed to load encryption key: " << encryption_key << std::endl;
        return 1;
      }
      set_encryption_enabled(true);
      std::cout << "Client-side encryption enabled" << std::endl;
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

  } else if (result["benchmark"].as<bool>()) {
    std::string dir = result["dir"].as<std::string>();
    if (dir.empty()) {
      std::cerr << "Error: --dir is required for benchmark mode" << std::endl;
      return 1;
    }

    ghostfs::BenchmarkConfig config;
    config.dir = dir;
    config.small_file_count = result["small-files"].as<uint32_t>();
    config.small_file_size = result["small-size"].as<uint32_t>();
    config.large_file_size_mb = result["large-size"].as<uint32_t>();
    config.parallel_jobs = result["jobs"].as<uint8_t>();
    config.verify = !result["no-verify"].as<bool>();

    return ghostfs::run_benchmark(config);

  } else if (is_copy_mode) {
    // Copy mode: GhostFS cp <source> <destination> [options]
    std::string source = result["cp-source"].as<std::string>();
    std::string destination = result["mountpoint"].as<std::string>();

    if (source.empty() || destination.empty()) {
      std::cerr << "Usage: GhostFS cp <source> <destination> [options]" << std::endl;
      std::cerr << "  Use gfs: prefix for GhostFS paths (e.g., gfs:/path/to/file)" << std::endl;
      std::cerr << "  Required for GhostFS paths: --host, --port, --user, --token" << std::endl;
      return 1;
    }

    ghostfs::CopyConfig copy_config;
    copy_config.source = source;
    copy_config.destination = destination;
    copy_config.host = result["host"].as<std::string>();
    copy_config.port = result["port"].as<uint16_t>();
    copy_config.user = result.count("user") ? result["user"].as<std::string>() : "";
    copy_config.token = result["token"].as<std::string>();
    copy_config.cert = result["cert"].as<std::string>();
    copy_config.encrypt = result["encrypt"].as<bool>();
    copy_config.encryption_key = result["encryption-key"].as<std::string>();
    copy_config.show_progress = result["progress"].as<bool>();

    return ghostfs::run_copy(copy_config);
  }

  // No mode specified - show help
  std::cout << options.help() << std::endl;
  return 1;
}
