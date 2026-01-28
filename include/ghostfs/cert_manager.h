#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace ghostfs::acme {

  // Forward declaration
  struct AcmeConfig;

  // Callback type for certificate reload notification
  // Parameters: cert_path, key_path
  using ReloadCallback = std::function<void(const std::string&, const std::string&)>;

  // Certificate manager handles automatic certificate renewal
  // and notifies servers when certificates are updated
  class CertManager {
  public:
    // Create a certificate manager with the given ACME configuration
    explicit CertManager(const AcmeConfig& config);
    ~CertManager();

    // Non-copyable, non-movable
    CertManager(const CertManager&) = delete;
    CertManager& operator=(const CertManager&) = delete;
    CertManager(CertManager&&) = delete;
    CertManager& operator=(CertManager&&) = delete;

    // Initialize the certificate manager
    // This loads existing certificates or requests new ones
    // Returns true on success
    bool init();

    // Get the current certificate and key paths
    // Returns empty pair if no valid certificate exists
    std::pair<std::string, std::string> get_cert_paths() const;

    // Check if the current certificate needs renewal
    // Returns true if certificate expires within the configured threshold
    bool needs_renewal() const;

    // Request a new certificate from Let's Encrypt
    // Returns true on success
    bool request_certificate();

    // Register a callback to be notified when certificates are reloaded
    // Multiple callbacks can be registered
    void on_reload(ReloadCallback callback);

    // Start the background renewal thread
    // This thread checks hourly if renewal is needed
    void start_renewal_loop();

    // Stop the background renewal thread and clean up
    void shutdown();

    // Get the challenge response for a given token
    // Used by HTTP server to respond to ACME challenges
    std::string get_challenge_response(const std::string& token) const;

    // Check if there's a pending ACME challenge
    bool has_pending_challenge() const;

    // Get certificate expiry time (Unix timestamp)
    // Returns 0 if no valid certificate exists
    int64_t get_expiry_time() const;

    // Get days until certificate expires
    // Returns -1 if no valid certificate exists
    int get_days_until_expiry() const;

    // Configuration getters
    const std::string& get_domain() const;
    bool is_staging() const;

  private:
    // Internal implementation
    class Impl;
    std::unique_ptr<Impl> impl_;
  };

  // Default certificate directory (~/.ghostfs/certs/)
  std::string get_default_cert_dir();

  // Certificate storage paths
  struct CertPaths {
    std::string account_key;  // ACME account private key
    std::string domain_dir;   // Per-domain directory
    std::string cert_pem;     // Fullchain certificate
    std::string key_pem;      // Domain private key
    std::string meta_json;    // Metadata (expiry, renewal dates)
  };

  // Get certificate paths for a domain
  CertPaths get_cert_paths(const std::string& cert_dir, const std::string& domain);

  // Read certificate metadata from JSON file
  struct CertMeta {
    int64_t expires_at = 0;    // Unix timestamp
    int64_t issued_at = 0;     // Unix timestamp
    int64_t last_renewal = 0;  // Unix timestamp of last renewal attempt
    std::string domain;
  };

  std::optional<CertMeta> read_cert_meta(const std::string& meta_path);
  bool write_cert_meta(const std::string& meta_path, const CertMeta& meta);

}  // namespace ghostfs::acme
