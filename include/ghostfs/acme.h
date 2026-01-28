#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ghostfs::acme {

// ACME directory URLs
constexpr const char* ACME_PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory";
constexpr const char* ACME_STAGING_URL =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

// Result of a certificate request
struct CertificateResult {
  bool success = false;
  std::string error;
  std::string cert_pem;       // Fullchain certificate (PEM)
  std::string private_key;    // Private key (PEM)
  int64_t expires_at = 0;     // Unix timestamp when certificate expires
};

// ACME configuration
struct AcmeConfig {
  std::string domain;             // Domain name for certificate
  std::string email;              // Email for Let's Encrypt registration
  bool staging = false;           // Use staging environment
  std::string cert_dir;           // Directory to store certificates
  uint16_t challenge_port = 80;   // Port for HTTP-01 challenge
  std::string account_key_path;   // Path to account key file
};

// Forward declarations
class AcmeClientImpl;

// ACME client for Let's Encrypt certificate management
// Implements ACME v2 protocol with HTTP-01 challenge
class AcmeClient {
public:
  explicit AcmeClient(const AcmeConfig& config);
  ~AcmeClient();

  // Non-copyable
  AcmeClient(const AcmeClient&) = delete;
  AcmeClient& operator=(const AcmeClient&) = delete;

  // Move constructors
  AcmeClient(AcmeClient&&) noexcept;
  AcmeClient& operator=(AcmeClient&&) noexcept;

  // Initialize the ACME client (load or create account key)
  // Returns true on success
  bool init();

  // Register a new account with the ACME server
  // Returns true on success
  bool register_account();

  // Request a new certificate for the configured domain
  // This performs the full ACME flow:
  // 1. Create order
  // 2. Get authorizations
  // 3. Complete HTTP-01 challenge
  // 4. Finalize order
  // 5. Download certificate
  CertificateResult request_certificate();

  // Get the challenge response for a given token
  // The HTTP server should serve this at /.well-known/acme-challenge/{token}
  std::string get_challenge_response(const std::string& token) const;

  // Check if there's a pending challenge
  bool has_pending_challenge() const;

  // Get the current challenge token (if any)
  std::optional<std::string> get_pending_challenge_token() const;

  // Set callback for when challenge token is ready
  // The callback receives the token and should start serving the challenge
  void set_challenge_callback(std::function<void(const std::string& token)> callback);

private:
  std::unique_ptr<AcmeClientImpl> impl_;
};

// Utility functions for certificate handling

// Parse a PEM certificate and extract the expiry date (Unix timestamp)
// Returns 0 on error
int64_t get_certificate_expiry(const std::string& cert_pem);

// Check if a certificate file exists and is valid
bool is_certificate_valid(const std::string& cert_path, int days_before_expiry = 30);

// Save a certificate and key to files atomically
// Creates parent directories if needed
bool save_certificate(const std::string& cert_path, const std::string& key_path,
                      const std::string& cert_pem, const std::string& key_pem);

// Load certificate and key from files
// Returns empty strings on error
std::pair<std::string, std::string> load_certificate(const std::string& cert_path,
                                                      const std::string& key_path);

}  // namespace ghostfs::acme
