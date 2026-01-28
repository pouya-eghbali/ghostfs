#include <fmt/format.h>
#include <ghostfs/acme.h>
#include <httplib.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace ghostfs::acme {

  // Base64 URL encoding (no padding, URL-safe characters)
  static std::string base64url_encode(const uint8_t* data, size_t len) {
    static const char* alphabet
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string result;
    result.reserve((len * 4 + 2) / 3);

    size_t i = 0;
    while (i + 2 < len) {
      uint32_t n = (static_cast<uint32_t>(data[i]) << 16)
                   | (static_cast<uint32_t>(data[i + 1]) << 8) | static_cast<uint32_t>(data[i + 2]);
      result += alphabet[(n >> 18) & 0x3F];
      result += alphabet[(n >> 12) & 0x3F];
      result += alphabet[(n >> 6) & 0x3F];
      result += alphabet[n & 0x3F];
      i += 3;
    }

    if (i + 1 == len) {
      uint32_t n = static_cast<uint32_t>(data[i]) << 16;
      result += alphabet[(n >> 18) & 0x3F];
      result += alphabet[(n >> 12) & 0x3F];
    } else if (i + 2 == len) {
      uint32_t n
          = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
      result += alphabet[(n >> 18) & 0x3F];
      result += alphabet[(n >> 12) & 0x3F];
      result += alphabet[(n >> 6) & 0x3F];
    }

    return result;
  }

  static std::string base64url_encode(const std::string& str) {
    return base64url_encode(reinterpret_cast<const uint8_t*>(str.data()), str.size());
  }

  // Simple JSON string extraction (we don't have a JSON library)
  static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";

    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
      pos++;
      auto end = json.find('"', pos);
      if (end == std::string::npos) return "";
      return json.substr(pos, end - pos);
    }

    return "";
  }

  // Extract array of strings from JSON
  static std::vector<std::string> json_get_string_array(const std::string& json,
                                                        const std::string& key) {
    std::vector<std::string> result;

    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;

    auto end = json.find(']', pos);
    if (end == std::string::npos) return result;

    std::string array_content = json.substr(pos + 1, end - pos - 1);

    size_t i = 0;
    while (i < array_content.size()) {
      auto quote_start = array_content.find('"', i);
      if (quote_start == std::string::npos) break;
      auto quote_end = array_content.find('"', quote_start + 1);
      if (quote_end == std::string::npos) break;
      result.push_back(array_content.substr(quote_start + 1, quote_end - quote_start - 1));
      i = quote_end + 1;
    }

    return result;
  }

  // SHA256 hash
  static std::vector<uint8_t> sha256(const std::string& data) {
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    return hash;
  }

  // Extract EC P-256 public key coordinates from EVP_PKEY (OpenSSL 3.0+ API)
  static bool get_ec_pub_coords(EVP_PKEY* key, std::vector<uint8_t>& x_bytes,
                                std::vector<uint8_t>& y_bytes) {
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;

    if (!EVP_PKEY_get_bn_param(key, "qx", &x) || !EVP_PKEY_get_bn_param(key, "qy", &y)) {
      BN_free(x);
      BN_free(y);
      return false;
    }

    x_bytes.resize(32);
    y_bytes.resize(32);
    BN_bn2binpad(x, x_bytes.data(), 32);
    BN_bn2binpad(y, y_bytes.data(), 32);

    BN_free(x);
    BN_free(y);
    return true;
  }

  // ACME client implementation
  class AcmeClientImpl {
  public:
    AcmeConfig config_;
    EVP_PKEY* account_key_ = nullptr;
    std::string account_url_;
    std::string directory_url_;

    // Directory endpoints
    std::string new_nonce_url_;
    std::string new_account_url_;
    std::string new_order_url_;

    // Challenge state
    mutable std::mutex challenge_mutex_;
    std::string pending_token_;
    std::string pending_key_auth_;
    std::function<void(const std::string&)> challenge_callback_;

    AcmeClientImpl(const AcmeConfig& config)
        : config_(config),
          directory_url_(config.staging ? ACME_STAGING_URL : ACME_PRODUCTION_URL) {}

    ~AcmeClientImpl() {
      if (account_key_) {
        EVP_PKEY_free(account_key_);
      }
    }

    // Load or create account key
    bool init() {
      // Ensure directory exists
      std::filesystem::create_directories(config_.cert_dir);

      std::string key_path = config_.account_key_path;
      if (key_path.empty()) {
        key_path = config_.cert_dir + "/account.key";
      }

      if (std::filesystem::exists(key_path)) {
        // Load existing key
        FILE* f = fopen(key_path.c_str(), "r");
        if (!f) {
          std::cerr << "Failed to open account key: " << key_path << std::endl;
          return false;
        }
        account_key_ = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        fclose(f);

        if (!account_key_) {
          std::cerr << "Failed to read account key" << std::endl;
          return false;
        }
      } else {
        // Generate new EC P-256 key
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          return false;
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          return false;
        }

        if (EVP_PKEY_keygen(ctx, &account_key_) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          return false;
        }
        EVP_PKEY_CTX_free(ctx);

        // Save key to file with restrictive permissions
        FILE* f = fopen(key_path.c_str(), "w");
        if (!f) {
          std::cerr << "Failed to create account key file" << std::endl;
          return false;
        }

        // Set file permissions to 0600
        chmod(key_path.c_str(), 0600);

        if (!PEM_write_PrivateKey(f, account_key_, nullptr, nullptr, 0, nullptr, nullptr)) {
          fclose(f);
          std::cerr << "Failed to write account key" << std::endl;
          return false;
        }
        fclose(f);
      }

      // Fetch ACME directory
      return fetch_directory();
    }

    bool fetch_directory() {
      std::string url = config_.staging ? "https://acme-staging-v02.api.letsencrypt.org"
                                        : "https://acme-v02.api.letsencrypt.org";
      httplib::Client cli(url);
      cli.enable_server_certificate_verification(true);

      auto res = cli.Get("/directory");
      if (!res || res->status != 200) {
        std::cerr << "Failed to fetch ACME directory" << std::endl;
        return false;
      }

      new_nonce_url_ = json_get_string(res->body, "newNonce");
      new_account_url_ = json_get_string(res->body, "newAccount");
      new_order_url_ = json_get_string(res->body, "newOrder");

      return !new_nonce_url_.empty() && !new_account_url_.empty() && !new_order_url_.empty();
    }

    std::string get_nonce() {
      std::string url = config_.staging ? "https://acme-staging-v02.api.letsencrypt.org"
                                        : "https://acme-v02.api.letsencrypt.org";
      httplib::Client cli(url);
      cli.enable_server_certificate_verification(true);

      // Extract path from URL
      auto path_start = new_nonce_url_.find('/', 8);  // Skip https://
      std::string path
          = (path_start != std::string::npos) ? new_nonce_url_.substr(path_start) : "/";

      auto res = cli.Head(path);
      if (res && res->has_header("Replay-Nonce")) {
        return res->get_header_value("Replay-Nonce");
      }
      return "";
    }

    // Get JWK thumbprint for key authorization
    std::string get_thumbprint() {
      std::vector<uint8_t> x_bytes, y_bytes;
      if (!get_ec_pub_coords(account_key_, x_bytes, y_bytes)) return "";

      // Create JWK (sorted keys for canonical form)
      std::string jwk = fmt::format(R"({{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}})",
                                    base64url_encode(x_bytes.data(), x_bytes.size()),
                                    base64url_encode(y_bytes.data(), y_bytes.size()));

      // SHA256 hash of JWK
      auto hash = sha256(jwk);
      return base64url_encode(hash.data(), hash.size());
    }

    // Sign data with ES256 and return JWS
    std::string sign_jws(const std::string& payload, const std::string& protected_header) {
      std::string signing_input = protected_header + "." + payload;

      // Hash the input
      auto hash = sha256(signing_input);

      // Sign with ECDSA
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, account_key_);
      EVP_DigestSignUpdate(ctx, signing_input.data(), signing_input.size());

      size_t sig_len = 0;
      EVP_DigestSignFinal(ctx, nullptr, &sig_len);

      std::vector<uint8_t> signature(sig_len);
      EVP_DigestSignFinal(ctx, signature.data(), &sig_len);
      EVP_MD_CTX_free(ctx);

      // Convert DER signature to fixed-size R||S format (64 bytes for P-256)
      const uint8_t* sig_ptr = signature.data();
      ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &sig_ptr, static_cast<long>(sig_len));
      if (!ecdsa_sig) return "";

      const BIGNUM* r;
      const BIGNUM* s;
      ECDSA_SIG_get0(ecdsa_sig, &r, &s);

      std::vector<uint8_t> rs_sig(64);
      BN_bn2binpad(r, rs_sig.data(), 32);
      BN_bn2binpad(s, rs_sig.data() + 32, 32);

      ECDSA_SIG_free(ecdsa_sig);

      return base64url_encode(rs_sig.data(), rs_sig.size());
    }

    // Build protected header with JWK (for new account)
    std::string build_protected_with_jwk(const std::string& nonce, const std::string& url) {
      std::vector<uint8_t> x_bytes, y_bytes;
      if (!get_ec_pub_coords(account_key_, x_bytes, y_bytes)) return "";

      std::string header = fmt::format(
          R"({{"alg":"ES256","jwk":{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}},"nonce":"{}","url":"{}"}})",
          base64url_encode(x_bytes.data(), x_bytes.size()),
          base64url_encode(y_bytes.data(), y_bytes.size()), nonce, url);

      return base64url_encode(header);
    }

    // Build protected header with kid (for authenticated requests)
    std::string build_protected_with_kid(const std::string& nonce, const std::string& url) {
      std::string header = fmt::format(R"({{"alg":"ES256","kid":"{}","nonce":"{}","url":"{}"}})",
                                       account_url_, nonce, url);
      return base64url_encode(header);
    }

    // Make ACME POST request
    httplib::Result acme_post(const std::string& url, const std::string& payload, bool use_kid) {
      std::string nonce = get_nonce();
      if (nonce.empty()) {
        std::cerr << "Failed to get nonce" << std::endl;
        return httplib::Result{nullptr, httplib::Error::Unknown};
      }

      std::string protected_header
          = use_kid ? build_protected_with_kid(nonce, url) : build_protected_with_jwk(nonce, url);

      std::string payload_b64 = payload.empty() ? "" : base64url_encode(payload);
      std::string signature = sign_jws(payload_b64, protected_header);

      std::string body = fmt::format(R"({{"protected":"{}","payload":"{}","signature":"{}"}})",
                                     protected_header, payload_b64, signature);

      // Extract host and path from URL
      std::string host;
      std::string path;
      if (url.find("https://") == 0) {
        auto host_start = 8;
        auto path_start = url.find('/', host_start);
        if (path_start != std::string::npos) {
          host = url.substr(host_start, path_start - host_start);
          path = url.substr(path_start);
        } else {
          host = url.substr(host_start);
          path = "/";
        }
      }

      httplib::Client cli("https://" + host);
      cli.enable_server_certificate_verification(true);

      httplib::Headers headers = {{"Content-Type", "application/jose+json"}};

      return cli.Post(path, headers, body, "application/jose+json");
    }

    bool register_account() {
      std::string payload = fmt::format(
          R"({{"termsOfServiceAgreed":true,"contact":["mailto:{}"]}})", config_.email);

      auto res = acme_post(new_account_url_, payload, false);
      if (!res) {
        std::cerr << "Account registration request failed" << std::endl;
        return false;
      }

      if (res->status == 200 || res->status == 201) {
        // Extract account URL from Location header
        if (res->has_header("Location")) {
          account_url_ = res->get_header_value("Location");
          return true;
        }
      }

      std::cerr << "Account registration failed: " << res->status << " " << res->body << std::endl;
      return false;
    }

    CertificateResult request_certificate() {
      CertificateResult result;

      // Create order
      std::string order_payload
          = fmt::format(R"({{"identifiers":[{{"type":"dns","value":"{}"}}]}})", config_.domain);

      auto order_res = acme_post(new_order_url_, order_payload, true);
      if (!order_res || (order_res->status != 200 && order_res->status != 201)) {
        result.error = "Failed to create order";
        return result;
      }

      std::string order_url = order_res->get_header_value("Location");
      std::string finalize_url = json_get_string(order_res->body, "finalize");
      auto authz_urls = json_get_string_array(order_res->body, "authorizations");

      if (authz_urls.empty()) {
        result.error = "No authorizations in order";
        return result;
      }

      // Get authorization and complete challenge
      for (const auto& authz_url : authz_urls) {
        if (!complete_challenge(authz_url)) {
          result.error = "Failed to complete challenge";
          return result;
        }
      }

      // Generate domain key and CSR
      EVP_PKEY* domain_key = nullptr;
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
      EVP_PKEY_keygen_init(ctx);
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
      EVP_PKEY_keygen(ctx, &domain_key);
      EVP_PKEY_CTX_free(ctx);

      // Create CSR
      X509_REQ* req = X509_REQ_new();
      X509_REQ_set_pubkey(req, domain_key);

      X509_NAME* name = X509_REQ_get_subject_name(req);
      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(config_.domain.c_str()), -1,
                                 -1, 0);

      X509_REQ_sign(req, domain_key, EVP_sha256());

      // Convert CSR to DER
      uint8_t* csr_der = nullptr;
      int csr_len = i2d_X509_REQ(req, &csr_der);
      X509_REQ_free(req);

      if (csr_len <= 0) {
        EVP_PKEY_free(domain_key);
        result.error = "Failed to create CSR";
        return result;
      }

      std::string csr_b64 = base64url_encode(csr_der, static_cast<size_t>(csr_len));
      OPENSSL_free(csr_der);

      // Finalize order
      std::string finalize_payload = fmt::format(R"({{"csr":"{}"}})", csr_b64);
      auto finalize_res = acme_post(finalize_url, finalize_payload, true);

      if (!finalize_res || (finalize_res->status != 200 && finalize_res->status != 201)) {
        EVP_PKEY_free(domain_key);
        result.error = "Failed to finalize order";
        return result;
      }

      // Poll for order completion
      std::string cert_url;
      for (int i = 0; i < 30; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        auto status_res = acme_post(order_url, "", true);
        if (!status_res) continue;

        std::string status = json_get_string(status_res->body, "status");
        if (status == "valid") {
          cert_url = json_get_string(status_res->body, "certificate");
          break;
        } else if (status == "invalid") {
          EVP_PKEY_free(domain_key);
          result.error = "Order became invalid";
          return result;
        }
      }

      if (cert_url.empty()) {
        EVP_PKEY_free(domain_key);
        result.error = "Order did not complete in time";
        return result;
      }

      // Download certificate
      auto cert_res = acme_post(cert_url, "", true);
      if (!cert_res || cert_res->status != 200) {
        EVP_PKEY_free(domain_key);
        result.error = "Failed to download certificate";
        return result;
      }

      result.cert_pem = cert_res->body;

      // Convert domain key to PEM
      BIO* bio = BIO_new(BIO_s_mem());
      PEM_write_bio_PrivateKey(bio, domain_key, nullptr, nullptr, 0, nullptr, nullptr);
      char* pem_data = nullptr;
      long pem_len = BIO_get_mem_data(bio, &pem_data);
      result.private_key = std::string(pem_data, static_cast<size_t>(pem_len));
      BIO_free(bio);

      EVP_PKEY_free(domain_key);

      // Extract expiry from certificate
      result.expires_at = get_certificate_expiry(result.cert_pem);
      result.success = true;

      return result;
    }

    bool complete_challenge(const std::string& authz_url) {
      // Get authorization
      auto authz_res = acme_post(authz_url, "", true);
      if (!authz_res || authz_res->status != 200) {
        return false;
      }

      // Find HTTP-01 challenge
      std::string challenge_url;
      std::string token;

      // Simple parsing for challenge
      auto body = authz_res->body;
      auto http_pos = body.find("\"http-01\"");
      if (http_pos == std::string::npos) {
        std::cerr << "No HTTP-01 challenge found" << std::endl;
        return false;
      }

      // Find the challenge object
      auto obj_start = body.rfind('{', http_pos);
      auto obj_end = body.find('}', http_pos);
      if (obj_start == std::string::npos || obj_end == std::string::npos) {
        return false;
      }

      std::string challenge_obj = body.substr(obj_start, obj_end - obj_start + 1);
      token = json_get_string(challenge_obj, "token");
      challenge_url = json_get_string(challenge_obj, "url");

      if (token.empty() || challenge_url.empty()) {
        std::cerr << "Failed to parse challenge" << std::endl;
        return false;
      }

      // Build key authorization
      std::string thumbprint = get_thumbprint();
      if (thumbprint.empty()) {
        std::cerr << "Failed to compute JWK thumbprint" << std::endl;
        return false;
      }
      std::string key_auth = token + "." + thumbprint;

      // Store challenge for HTTP server
      {
        std::lock_guard<std::mutex> lock(challenge_mutex_);
        pending_token_ = token;
        pending_key_auth_ = key_auth;
      }

      // Notify callback if set
      if (challenge_callback_) {
        challenge_callback_(token);
      }

      // Start temporary HTTP server to serve the challenge response
      auto challenge_server = std::make_unique<httplib::Server>();
      std::string challenge_key_auth = key_auth;
      std::string challenge_token = token;

      std::cout << "Challenge token: " << token << std::endl;
      std::cout << "Key authorization length: " << key_auth.size() << std::endl;

      challenge_server->Get(R"(/\.well-known/acme-challenge/(.+))",
                            [&challenge_token, &challenge_key_auth](const httplib::Request& req,
                                                                    httplib::Response& res) {
                              auto req_token = req.matches[1].str();
                              std::cout << "Challenge request for token: " << req_token
                                        << std::endl;
                              if (req_token == challenge_token) {
                                std::cout << "Serving key authorization" << std::endl;
                                res.set_content(challenge_key_auth, "text/plain");
                              } else {
                                std::cout << "Token mismatch, returning 404" << std::endl;
                                res.status = 404;
                              }
                            });

      auto* svr_ptr = challenge_server.get();
      std::thread server_thread([svr_ptr, this]() {
        std::cout << "Starting challenge server on port " << config_.challenge_port << std::endl;
        svr_ptr->listen("0.0.0.0", config_.challenge_port);
      });

      // Wait briefly for server to start
      for (int i = 0; i < 50 && !svr_ptr->is_running(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }

      if (!svr_ptr->is_running()) {
        std::cerr << "Failed to start challenge server on port " << config_.challenge_port
                  << std::endl;
        if (server_thread.joinable()) server_thread.join();
        return false;
      }

      // Respond to challenge (tell ACME server we're ready)
      std::cout << "Notifying ACME server to validate challenge..." << std::endl;
      auto challenge_res = acme_post(challenge_url, "{}", true);
      if (!challenge_res) {
        std::cerr << "Failed to POST challenge response" << std::endl;
        svr_ptr->stop();
        if (server_thread.joinable()) server_thread.join();
        return false;
      }
      std::cout << "Challenge response status: " << challenge_res->status << std::endl;

      // Poll for challenge completion
      bool success = false;
      for (int i = 0; i < 30; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        auto status_res = acme_post(authz_url, "", true);
        if (!status_res) continue;

        std::string status = json_get_string(status_res->body, "status");
        if (status == "valid") {
          // Clear challenge
          std::lock_guard<std::mutex> lock(challenge_mutex_);
          pending_token_.clear();
          pending_key_auth_.clear();
          success = true;
          break;
        } else if (status == "invalid") {
          std::cerr << "Challenge became invalid" << std::endl;
          std::cerr << "Response: " << status_res->body << std::endl;
          break;
        }
      }

      // Stop temporary challenge server
      svr_ptr->stop();
      if (server_thread.joinable()) server_thread.join();

      return success;
    }

    std::string get_challenge_response(const std::string& token) const {
      std::lock_guard<std::mutex> lock(challenge_mutex_);
      if (token == pending_token_) {
        return pending_key_auth_;
      }
      return "";
    }

    bool has_pending_challenge() const {
      std::lock_guard<std::mutex> lock(challenge_mutex_);
      return !pending_token_.empty();
    }

    std::optional<std::string> get_pending_challenge_token() const {
      std::lock_guard<std::mutex> lock(challenge_mutex_);
      if (pending_token_.empty()) {
        return std::nullopt;
      }
      return pending_token_;
    }
  };

  // AcmeClient implementation
  AcmeClient::AcmeClient(const AcmeConfig& config)
      : impl_(std::make_unique<AcmeClientImpl>(config)) {}

  AcmeClient::~AcmeClient() = default;

  AcmeClient::AcmeClient(AcmeClient&&) noexcept = default;
  AcmeClient& AcmeClient::operator=(AcmeClient&&) noexcept = default;

  bool AcmeClient::init() { return impl_->init(); }

  bool AcmeClient::register_account() { return impl_->register_account(); }

  CertificateResult AcmeClient::request_certificate() { return impl_->request_certificate(); }

  std::string AcmeClient::get_challenge_response(const std::string& token) const {
    return impl_->get_challenge_response(token);
  }

  bool AcmeClient::has_pending_challenge() const { return impl_->has_pending_challenge(); }

  std::optional<std::string> AcmeClient::get_pending_challenge_token() const {
    return impl_->get_pending_challenge_token();
  }

  void AcmeClient::set_challenge_callback(std::function<void(const std::string& token)> callback) {
    impl_->challenge_callback_ = std::move(callback);
  }

  // Utility functions
  int64_t get_certificate_expiry(const std::string& cert_pem) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (!bio) return 0;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return 0;

    ASN1_TIME* not_after = X509_get_notAfter(cert);
    struct tm tm;
    ASN1_TIME_to_tm(not_after, &tm);
    X509_free(cert);

    return static_cast<int64_t>(timegm(&tm));
  }

  bool is_certificate_valid(const std::string& cert_path, int days_before_expiry) {
    if (!std::filesystem::exists(cert_path)) {
      return false;
    }

    std::ifstream file(cert_path);
    if (!file) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string cert_pem = buffer.str();

    int64_t expiry = get_certificate_expiry(cert_pem);
    if (expiry == 0) return false;

    auto now = std::chrono::system_clock::now();
    auto expiry_time = std::chrono::system_clock::from_time_t(static_cast<time_t>(expiry));
    auto threshold = std::chrono::hours(days_before_expiry * 24);

    return (expiry_time - now) > threshold;
  }

  bool save_certificate(const std::string& cert_path, const std::string& key_path,
                        const std::string& cert_pem, const std::string& key_pem) {
    // Create parent directories
    std::filesystem::create_directories(std::filesystem::path(cert_path).parent_path());
    std::filesystem::create_directories(std::filesystem::path(key_path).parent_path());

    // Write to temp files first
    std::string cert_tmp = cert_path + ".tmp";
    std::string key_tmp = key_path + ".tmp";

    {
      std::ofstream file(cert_tmp);
      if (!file) return false;
      file << cert_pem;
    }

    {
      std::ofstream file(key_tmp);
      if (!file) {
        std::filesystem::remove(cert_tmp);
        return false;
      }
      file << key_pem;
      // Set restrictive permissions on key
      chmod(key_tmp.c_str(), 0600);
    }

    // Atomically rename
    std::error_code ec;
    std::filesystem::rename(cert_tmp, cert_path, ec);
    if (ec) {
      std::filesystem::remove(cert_tmp);
      std::filesystem::remove(key_tmp);
      return false;
    }

    std::filesystem::rename(key_tmp, key_path, ec);
    if (ec) {
      std::filesystem::remove(key_tmp);
      return false;
    }

    return true;
  }

  std::pair<std::string, std::string> load_certificate(const std::string& cert_path,
                                                       const std::string& key_path) {
    std::pair<std::string, std::string> result;

    if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path)) {
      return result;
    }

    {
      std::ifstream file(cert_path);
      if (!file) return result;
      std::stringstream buffer;
      buffer << file.rdbuf();
      result.first = buffer.str();
    }

    {
      std::ifstream file(key_path);
      if (!file) return result;
      std::stringstream buffer;
      buffer << file.rdbuf();
      result.second = buffer.str();
    }

    return result;
  }

}  // namespace ghostfs::acme
