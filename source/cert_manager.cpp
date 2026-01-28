#include <fmt/format.h>
#include <ghostfs/acme.h>
#include <ghostfs/cert_manager.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace ghostfs::acme {

  // Default certificate directory
  std::string get_default_cert_dir() {
    const char* home = std::getenv("HOME");
    if (!home) {
      home = "/tmp";
    }
    return std::string(home) + "/.ghostfs/certs";
  }

  // Get certificate paths for a domain
  CertPaths get_cert_paths(const std::string& cert_dir, const std::string& domain) {
    CertPaths paths;
    paths.account_key = cert_dir + "/account.key";
    paths.domain_dir = cert_dir + "/" + domain;
    paths.cert_pem = paths.domain_dir + "/cert.pem";
    paths.key_pem = paths.domain_dir + "/key.pem";
    paths.meta_json = paths.domain_dir + "/meta.json";
    return paths;
  }

  // Simple JSON parsing for metadata
  std::optional<CertMeta> read_cert_meta(const std::string& meta_path) {
    if (!std::filesystem::exists(meta_path)) {
      return std::nullopt;
    }

    std::ifstream file(meta_path);
    if (!file) {
      return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();

    CertMeta meta;

    // Parse JSON (simple extraction)
    auto extract_int64 = [&json](const std::string& key) -> int64_t {
      std::string search = "\"" + key + "\"";
      auto pos = json.find(search);
      if (pos == std::string::npos) return 0;

      pos = json.find(':', pos);
      if (pos == std::string::npos) return 0;

      pos++;
      while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

      auto end = json.find_first_of(",}", pos);
      std::string val = json.substr(pos, end - pos);
      try {
        return std::stoll(val);
      } catch (...) {
        return 0;
      }
    };

    auto extract_string = [&json](const std::string& key) -> std::string {
      std::string search = "\"" + key + "\"";
      auto pos = json.find(search);
      if (pos == std::string::npos) return "";

      pos = json.find(':', pos);
      if (pos == std::string::npos) return "";

      pos++;
      while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

      if (pos >= json.size() || json[pos] != '"') return "";
      pos++;
      auto end = json.find('"', pos);
      if (end == std::string::npos) return "";
      return json.substr(pos, end - pos);
    };

    meta.expires_at = extract_int64("expires_at");
    meta.issued_at = extract_int64("issued_at");
    meta.last_renewal = extract_int64("last_renewal");
    meta.domain = extract_string("domain");

    return meta;
  }

  bool write_cert_meta(const std::string& meta_path, const CertMeta& meta) {
    std::filesystem::create_directories(std::filesystem::path(meta_path).parent_path());

    std::string temp_path = meta_path + ".tmp";

    {
      std::ofstream file(temp_path);
      if (!file) return false;

      file << fmt::format(
          R"({{
  "domain": "{}",
  "expires_at": {},
  "issued_at": {},
  "last_renewal": {}
}})",
          meta.domain, meta.expires_at, meta.issued_at, meta.last_renewal);
    }

    std::error_code ec;
    std::filesystem::rename(temp_path, meta_path, ec);
    return !ec;
  }

  // CertManager implementation
  class CertManager::Impl {
  public:
    AcmeConfig config_;
    std::unique_ptr<AcmeClient> acme_client_;
    CertPaths paths_;

    std::mutex mutex_;
    std::vector<ReloadCallback> reload_callbacks_;

    std::atomic<bool> running_{false};
    std::thread renewal_thread_;

    int64_t expiry_time_ = 0;

    explicit Impl(const AcmeConfig& config) : config_(config) {
      if (config_.cert_dir.empty()) {
        config_.cert_dir = get_default_cert_dir();
      }
      paths_ = ::ghostfs::acme::get_cert_paths(config_.cert_dir, config_.domain);
      config_.account_key_path = paths_.account_key;
    }

    ~Impl() { shutdown(); }

    bool init() {
      // Create ACME client
      acme_client_ = std::make_unique<AcmeClient>(config_);

      if (!acme_client_->init()) {
        std::cerr << "Failed to initialize ACME client" << std::endl;
        return false;
      }

      // Check if we have a valid certificate
      if (is_certificate_valid(paths_.cert_pem, 30)) {
        auto meta = read_cert_meta(paths_.meta_json);
        if (meta) {
          expiry_time_ = meta->expires_at;
        } else {
          // Read expiry from certificate
          auto [cert, key] = load_certificate(paths_.cert_pem, paths_.key_pem);
          expiry_time_ = get_certificate_expiry(cert);
        }
        std::cout << "Using existing certificate for " << config_.domain << std::endl;
        return true;
      }

      // Need to request a new certificate
      std::cout << "Requesting new certificate for " << config_.domain << std::endl;
      return request_certificate();
    }

    std::pair<std::string, std::string> get_cert_paths() const {
      if (std::filesystem::exists(paths_.cert_pem) && std::filesystem::exists(paths_.key_pem)) {
        return {paths_.cert_pem, paths_.key_pem};
      }
      return {};
    }

    bool needs_renewal() const {
      if (expiry_time_ == 0) return true;

      auto now = std::chrono::system_clock::now();
      auto expiry = std::chrono::system_clock::from_time_t(static_cast<time_t>(expiry_time_));
      auto threshold = std::chrono::hours(30 * 24);  // 30 days

      return (expiry - now) < threshold;
    }

    bool request_certificate() {
      // Register account if needed
      if (!acme_client_->register_account()) {
        std::cerr << "Failed to register ACME account" << std::endl;
        return false;
      }

      // Request certificate
      auto result = acme_client_->request_certificate();

      if (!result.success) {
        std::cerr << "Certificate request failed: " << result.error << std::endl;
        return false;
      }

      // Save certificate
      if (!save_certificate(paths_.cert_pem, paths_.key_pem, result.cert_pem, result.private_key)) {
        std::cerr << "Failed to save certificate" << std::endl;
        return false;
      }

      // Update metadata
      CertMeta meta;
      meta.domain = config_.domain;
      meta.expires_at = result.expires_at;
      meta.issued_at = static_cast<int64_t>(
          std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
      meta.last_renewal = meta.issued_at;

      write_cert_meta(paths_.meta_json, meta);

      expiry_time_ = result.expires_at;

      std::cout << "Certificate obtained for " << config_.domain << std::endl;

      // Notify callbacks
      notify_reload();

      return true;
    }

    void on_reload(ReloadCallback callback) {
      std::lock_guard<std::mutex> lock(mutex_);
      reload_callbacks_.push_back(std::move(callback));
    }

    void notify_reload() {
      std::lock_guard<std::mutex> lock(mutex_);
      for (const auto& callback : reload_callbacks_) {
        try {
          callback(paths_.cert_pem, paths_.key_pem);
        } catch (const std::exception& e) {
          std::cerr << "Reload callback error: " << e.what() << std::endl;
        }
      }
    }

    void start_renewal_loop() {
      if (running_) return;

      running_ = true;
      renewal_thread_ = std::thread([this]() { renewal_loop(); });
    }

    void shutdown() {
      running_ = false;
      if (renewal_thread_.joinable()) {
        renewal_thread_.join();
      }
    }

    void renewal_loop() {
      while (running_) {
        // Check every hour
        for (int i = 0; i < 60 && running_; i++) {
          std::this_thread::sleep_for(std::chrono::minutes(1));
        }

        if (!running_) break;

        if (needs_renewal()) {
          std::cout << "Certificate renewal needed for " << config_.domain << std::endl;
          if (request_certificate()) {
            std::cout << "Certificate renewed successfully" << std::endl;
          } else {
            std::cerr << "Certificate renewal failed, will retry later" << std::endl;
          }
        }
      }
    }

    std::string get_challenge_response(const std::string& token) const {
      if (acme_client_) {
        return acme_client_->get_challenge_response(token);
      }
      return "";
    }

    bool has_pending_challenge() const {
      if (acme_client_) {
        return acme_client_->has_pending_challenge();
      }
      return false;
    }

    int64_t get_expiry_time() const { return expiry_time_; }

    int get_days_until_expiry() const {
      if (expiry_time_ == 0) return -1;

      auto now = std::chrono::system_clock::now();
      auto expiry = std::chrono::system_clock::from_time_t(static_cast<time_t>(expiry_time_));
      auto duration = expiry - now;

      return static_cast<int>(std::chrono::duration_cast<std::chrono::hours>(duration).count()
                              / 24);
    }
  };

  // CertManager public interface
  CertManager::CertManager(const AcmeConfig& config) : impl_(std::make_unique<Impl>(config)) {}

  CertManager::~CertManager() = default;

  bool CertManager::init() { return impl_->init(); }

  std::pair<std::string, std::string> CertManager::get_cert_paths() const {
    return impl_->get_cert_paths();
  }

  bool CertManager::needs_renewal() const { return impl_->needs_renewal(); }

  bool CertManager::request_certificate() { return impl_->request_certificate(); }

  void CertManager::on_reload(ReloadCallback callback) { impl_->on_reload(std::move(callback)); }

  void CertManager::start_renewal_loop() { impl_->start_renewal_loop(); }

  void CertManager::shutdown() { impl_->shutdown(); }

  std::string CertManager::get_challenge_response(const std::string& token) const {
    return impl_->get_challenge_response(token);
  }

  bool CertManager::has_pending_challenge() const { return impl_->has_pending_challenge(); }

  int64_t CertManager::get_expiry_time() const { return impl_->get_expiry_time(); }

  int CertManager::get_days_until_expiry() const { return impl_->get_days_until_expiry(); }

  const std::string& CertManager::get_domain() const { return impl_->config_.domain; }

  bool CertManager::is_staging() const { return impl_->config_.staging; }

}  // namespace ghostfs::acme
