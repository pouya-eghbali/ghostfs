#include <ghostfs/http.h>

#include <ghostfs/auth.h>
#include <ghostfs/crypto.h>
#include <ghostfs/rpc.h>
#include <ghostfs/uuid.h>

#include <fmt/format.h>

#include <httplib.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <sys/stat.h>

namespace ghostfs::http {

// Constants
constexpr auto SESSION_TIMEOUT = std::chrono::hours(24);

// Session data structure
struct HttpSession {
  std::string sessionId;
  std::string user;
  std::string root;  // User's root directory path
  std::chrono::steady_clock::time_point lastAccess;
  std::optional<std::array<uint8_t, 32>> encryptionKey;
};

// Global state
static std::map<std::string, HttpSession> sessions;
static std::mutex sessions_mutex;
static std::string g_root;
static std::string g_suffix;
static uint16_t g_rpc_port;
static uint16_t g_auth_port;

// ACME challenge callback
static AcmeChallengeCallback g_acme_challenge_callback;
static std::mutex g_acme_mutex;

void set_acme_challenge_callback(AcmeChallengeCallback callback) {
  std::lock_guard<std::mutex> lock(g_acme_mutex);
  g_acme_challenge_callback = std::move(callback);
}

// Helper: Generate session ID
static std::string generate_session_id() { return gen_uuid(); }

// Helper: Get session from request
static HttpSession* get_session(const httplib::Request& req) {
  auto it = req.headers.find("X-Session-Id");
  if (it == req.headers.end()) {
    return nullptr;
  }

  std::lock_guard<std::mutex> lock(sessions_mutex);
  auto session_it = sessions.find(it->second);
  if (session_it == sessions.end()) {
    return nullptr;
  }

  // Check session expiry
  auto now = std::chrono::steady_clock::now();
  if (now - session_it->second.lastAccess > SESSION_TIMEOUT) {
    sessions.erase(session_it);
    return nullptr;
  }

  // Update last access time
  session_it->second.lastAccess = now;
  return &session_it->second;
}

// Helper: Resolve path for session user
static std::filesystem::path resolve_path(const HttpSession& session, const std::string& path) {
  // Normalize the path to prevent directory traversal
  std::filesystem::path user_root = session.root;
  std::filesystem::path requested;

  if (path.empty() || path == "/") {
    requested = user_root;
  } else {
    // Remove leading slash if present
    std::string clean_path = path;
    if (!clean_path.empty() && clean_path[0] == '/') {
      clean_path = clean_path.substr(1);
    }
    requested = user_root / clean_path;
  }

  // Normalize to prevent ../ attacks
  auto normalized = requested.lexically_normal();

  // Verify the path is under user root
  auto root_str = user_root.string();
  auto path_str = normalized.string();

  if (path_str.find(root_str) != 0) {
    return {};  // Path traversal attempt
  }

  return normalized;
}

// Helper: Set CORS headers
static void set_cors_headers(httplib::Response& res) {
  res.set_header("Access-Control-Allow-Origin", "*");
  res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set_header("Access-Control-Allow-Headers", "Content-Type, X-Session-Id");
  res.set_header("Access-Control-Max-Age", "86400");
}

// Helper: Send JSON response
static void json_response(httplib::Response& res, int status, const std::string& json) {
  set_cors_headers(res);
  res.status = status;
  res.set_content(json, "application/json");
}

// Helper: Send error response
static void error_response(httplib::Response& res, int status, const std::string& message) {
  json_response(res, status, fmt::format(R"({{"success":false,"error":"{}"}})", message));
}

// Helper: Get MIME type from extension
static std::string get_mime_type(const std::string& path) {
  static const std::map<std::string, std::string> mime_types = {
      {".html", "text/html"},
      {".htm", "text/html"},
      {".css", "text/css"},
      {".js", "application/javascript"},
      {".mjs", "application/javascript"},
      {".json", "application/json"},
      {".png", "image/png"},
      {".jpg", "image/jpeg"},
      {".jpeg", "image/jpeg"},
      {".gif", "image/gif"},
      {".svg", "image/svg+xml"},
      {".ico", "image/x-icon"},
      {".woff", "font/woff"},
      {".woff2", "font/woff2"},
      {".ttf", "font/ttf"},
      {".txt", "text/plain"},
      {".md", "text/markdown"},
      {".pdf", "application/pdf"},
      {".zip", "application/zip"},
      {".tar", "application/x-tar"},
      {".gz", "application/gzip"},
  };

  auto ext_pos = path.rfind('.');
  if (ext_pos != std::string::npos) {
    std::string ext = path.substr(ext_pos);
    // Convert to lowercase
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    auto it = mime_types.find(ext);
    if (it != mime_types.end()) {
      return it->second;
    }
  }
  return "application/octet-stream";
}

// Handler: OPTIONS (CORS preflight)
static void handle_options(const httplib::Request& /*req*/, httplib::Response& res) {
  set_cors_headers(res);
  res.status = 204;
}

// Handler: POST /api/auth/login
static void handle_login(const httplib::Request& req, httplib::Response& res) {
  try {
    // Parse JSON body
    // Expected: { "host": "...", "port": ..., "user": "...", "token": "...", "encryptionKey"?: "..." }

    // Simple JSON parsing (we don't have a JSON library, so do basic parsing)
    std::string body = req.body;

    // Extract fields using simple string search
    auto extract_string = [&body](const std::string& key) -> std::string {
      std::string search = "\"" + key + "\"";
      auto pos = body.find(search);
      if (pos == std::string::npos) return "";

      pos = body.find(':', pos);
      if (pos == std::string::npos) return "";

      // Skip whitespace
      pos++;
      while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;

      if (pos >= body.size()) return "";

      if (body[pos] == '"') {
        // String value
        pos++;
        auto end = body.find('"', pos);
        if (end == std::string::npos) return "";
        return body.substr(pos, end - pos);
      } else if (body[pos] == 'n' && body.substr(pos, 4) == "null") {
        return "";
      } else {
        // Number or other
        auto end = body.find_first_of(",}", pos);
        if (end == std::string::npos) end = body.size();
        std::string val = body.substr(pos, end - pos);
        // Trim whitespace
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\n'))
          val.pop_back();
        return val;
      }
    };

    std::string user = extract_string("user");
    std::string token = extract_string("token");
    std::string encryption_key_hex = extract_string("encryptionKey");

    if (user.empty() || token.empty()) {
      error_response(res, 400, "Missing user or token");
      return;
    }

    // Authenticate using the existing auth system
    if (!authenticate(token, user)) {
      error_response(res, 401, "Invalid credentials");
      return;
    }

    // Create session
    HttpSession session;
    session.sessionId = generate_session_id();
    session.user = user;
    session.root = normalize_path(g_root, user, g_suffix).string();
    session.lastAccess = std::chrono::steady_clock::now();

    // Handle encryption key if provided
    if (!encryption_key_hex.empty()) {
      // Parse hex-encoded key
      if (encryption_key_hex.size() == 64) {  // 32 bytes = 64 hex chars
        std::array<uint8_t, 32> key;
        for (size_t i = 0; i < 32; i++) {
          std::string byte_str = encryption_key_hex.substr(i * 2, 2);
          key[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }
        session.encryptionKey = key;
      }
    }

    // Ensure user directory exists
    std::filesystem::create_directories(session.root);

    std::string session_id = session.sessionId;

    {
      std::lock_guard<std::mutex> lock(sessions_mutex);
      sessions[session_id] = std::move(session);
    }

    json_response(res, 200,
                  fmt::format(R"({{"success":true,"sessionId":"{}"}})", session_id));
  } catch (const std::exception& e) {
    error_response(res, 500, fmt::format("Login error: {}", e.what()));
  } catch (...) {
    error_response(res, 500, "Unknown login error");
  }
}

// Handler: POST /api/auth/logout
static void handle_logout(const httplib::Request& req, httplib::Response& res) {
  auto it = req.headers.find("X-Session-Id");
  if (it != req.headers.end()) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    sessions.erase(it->second);
  }

  json_response(res, 200, R"({"success":true})");
}

// Handler: GET /api/auth/status
static void handle_auth_status(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    json_response(res, 200, R"({"authenticated":false})");
    return;
  }

  json_response(res, 200,
                fmt::format(R"({{"authenticated":true,"user":"{}"}})", session->user));
}

// Handler: GET /api/fs/list
static void handle_list(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  std::string path = req.get_param_value("path");
  auto resolved = resolve_path(*session, path);
  if (resolved.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  if (!std::filesystem::exists(resolved)) {
    error_response(res, 404, "Path not found");
    return;
  }

  if (!std::filesystem::is_directory(resolved)) {
    error_response(res, 400, "Path is not a directory");
    return;
  }

  std::string entries_json = "[";
  bool first = true;

  try {
    for (const auto& entry :
         std::filesystem::directory_iterator(resolved,
                                             std::filesystem::directory_options::skip_permission_denied)) {
      if (!first) entries_json += ",";
      first = false;

      std::string name = entry.path().filename().string();
      bool is_dir = entry.is_directory();
      int64_t size = 0;
      int64_t mtime = 0;

      try {
        if (!is_dir) {
          size = static_cast<int64_t>(entry.file_size());
        }
        auto ftime = entry.last_write_time();
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::file_clock::to_sys(ftime));
        mtime = sctp.time_since_epoch().count();
      } catch (...) {
        // Ignore errors getting metadata
      }

      // Escape name for JSON
      std::string escaped_name;
      for (char c : name) {
        if (c == '"')
          escaped_name += "\\\"";
        else if (c == '\\')
          escaped_name += "\\\\";
        else if (c == '\n')
          escaped_name += "\\n";
        else if (c == '\r')
          escaped_name += "\\r";
        else if (c == '\t')
          escaped_name += "\\t";
        else
          escaped_name += c;
      }

      entries_json += fmt::format(
          R"({{"name":"{}","isDir":{},"size":{},"mtime":{}}})",
          escaped_name, is_dir ? "true" : "false", size, mtime);
    }
  } catch (const std::exception& e) {
    error_response(res, 500, fmt::format("Error reading directory: {}", e.what()));
    return;
  }

  entries_json += "]";
  json_response(res, 200, fmt::format(R"({{"success":true,"entries":{}}})", entries_json));
}

// Handler: GET /api/fs/stat
static void handle_stat(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  std::string path = req.get_param_value("path");
  auto resolved = resolve_path(*session, path);
  if (resolved.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  struct stat st;
  if (::stat(resolved.c_str(), &st) != 0) {
    error_response(res, 404, "Path not found");
    return;
  }

  std::string name = resolved.filename().string();
  bool is_dir = S_ISDIR(st.st_mode);

  // Escape name for JSON
  std::string escaped_name;
  for (char c : name) {
    if (c == '"')
      escaped_name += "\\\"";
    else if (c == '\\')
      escaped_name += "\\\\";
    else
      escaped_name += c;
  }

  json_response(res, 200,
                fmt::format(R"({{"success":true,"stat":{{"name":"{}","isDir":{},"size":{},"mode":{},"mtime":{}}}}})",
                            escaped_name, is_dir ? "true" : "false",
                            static_cast<int64_t>(st.st_size),
                            static_cast<int>(st.st_mode),
                            static_cast<int64_t>(st.st_mtime)));
}

// Handler: POST /api/fs/mkdir
static void handle_mkdir(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  // Parse JSON body
  auto extract_string = [&](const std::string& key) -> std::string {
    std::string search = "\"" + key + "\"";
    auto pos = req.body.find(search);
    if (pos == std::string::npos) return "";
    pos = req.body.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < req.body.size() && (req.body[pos] == ' ' || req.body[pos] == '\t')) pos++;
    if (pos >= req.body.size() || req.body[pos] != '"') return "";
    pos++;
    auto end = req.body.find('"', pos);
    if (end == std::string::npos) return "";
    return req.body.substr(pos, end - pos);
  };

  std::string path = extract_string("path");
  if (path.empty()) {
    error_response(res, 400, "Missing path");
    return;
  }

  auto resolved = resolve_path(*session, path);
  if (resolved.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  std::error_code ec;
  if (!std::filesystem::create_directories(resolved, ec)) {
    if (ec) {
      error_response(res, 500, fmt::format("Failed to create directory: {}", ec.message()));
      return;
    }
    // Directory already exists
  }

  json_response(res, 200, R"({"success":true})");
}

// Handler: DELETE /api/fs/delete (uses POST with body for compatibility)
static void handle_delete(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  // Parse JSON body
  auto extract_string = [&](const std::string& key) -> std::string {
    std::string search = "\"" + key + "\"";
    auto pos = req.body.find(search);
    if (pos == std::string::npos) return "";
    pos = req.body.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < req.body.size() && (req.body[pos] == ' ' || req.body[pos] == '\t')) pos++;
    if (pos >= req.body.size()) return "";
    if (req.body[pos] == '"') {
      pos++;
      auto end = req.body.find('"', pos);
      if (end == std::string::npos) return "";
      return req.body.substr(pos, end - pos);
    }
    auto end = req.body.find_first_of(",}", pos);
    return req.body.substr(pos, end - pos);
  };

  std::string path = extract_string("path");
  std::string is_dir_str = extract_string("isDir");
  bool is_dir = (is_dir_str == "true");

  if (path.empty()) {
    error_response(res, 400, "Missing path");
    return;
  }

  auto resolved = resolve_path(*session, path);
  if (resolved.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  if (!std::filesystem::exists(resolved)) {
    error_response(res, 404, "Path not found");
    return;
  }

  std::error_code ec;
  if (is_dir) {
    std::filesystem::remove_all(resolved, ec);
  } else {
    std::filesystem::remove(resolved, ec);
  }

  if (ec) {
    error_response(res, 500, fmt::format("Failed to delete: {}", ec.message()));
    return;
  }

  json_response(res, 200, R"({"success":true})");
}

// Handler: POST /api/fs/rename
static void handle_rename(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  // Parse JSON body
  auto extract_string = [&](const std::string& key) -> std::string {
    std::string search = "\"" + key + "\"";
    auto pos = req.body.find(search);
    if (pos == std::string::npos) return "";
    pos = req.body.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < req.body.size() && (req.body[pos] == ' ' || req.body[pos] == '\t')) pos++;
    if (pos >= req.body.size() || req.body[pos] != '"') return "";
    pos++;
    auto end = req.body.find('"', pos);
    if (end == std::string::npos) return "";
    return req.body.substr(pos, end - pos);
  };

  std::string old_path = extract_string("oldPath");
  std::string new_path = extract_string("newPath");

  if (old_path.empty() || new_path.empty()) {
    error_response(res, 400, "Missing oldPath or newPath");
    return;
  }

  auto resolved_old = resolve_path(*session, old_path);
  auto resolved_new = resolve_path(*session, new_path);

  if (resolved_old.empty() || resolved_new.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  if (!std::filesystem::exists(resolved_old)) {
    error_response(res, 404, "Source path not found");
    return;
  }

  std::error_code ec;
  std::filesystem::rename(resolved_old, resolved_new, ec);

  if (ec) {
    error_response(res, 500, fmt::format("Failed to rename: {}", ec.message()));
    return;
  }

  json_response(res, 200, R"({"success":true})");
}

// Handler: POST /api/fs/copy
static void handle_copy(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  // Parse JSON body
  auto extract_string = [&](const std::string& key) -> std::string {
    std::string search = "\"" + key + "\"";
    auto pos = req.body.find(search);
    if (pos == std::string::npos) return "";
    pos = req.body.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < req.body.size() && (req.body[pos] == ' ' || req.body[pos] == '\t')) pos++;
    if (pos >= req.body.size() || req.body[pos] != '"') return "";
    pos++;
    auto end = req.body.find('"', pos);
    if (end == std::string::npos) return "";
    return req.body.substr(pos, end - pos);
  };

  std::string src_path = extract_string("srcPath");
  std::string dest_path = extract_string("destPath");

  if (src_path.empty() || dest_path.empty()) {
    error_response(res, 400, "Missing srcPath or destPath");
    return;
  }

  auto resolved_src = resolve_path(*session, src_path);
  auto resolved_dest = resolve_path(*session, dest_path);

  if (resolved_src.empty() || resolved_dest.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  if (!std::filesystem::exists(resolved_src)) {
    error_response(res, 404, "Source path not found");
    return;
  }

  std::error_code ec;
  if (std::filesystem::is_directory(resolved_src)) {
    std::filesystem::copy(resolved_src, resolved_dest,
                          std::filesystem::copy_options::recursive, ec);
  } else {
    std::filesystem::copy_file(resolved_src, resolved_dest,
                               std::filesystem::copy_options::overwrite_existing, ec);
  }

  if (ec) {
    error_response(res, 500, fmt::format("Failed to copy: {}", ec.message()));
    return;
  }

  json_response(res, 200, R"({"success":true})");
}

// Handler: GET /api/fs/download
static void handle_download(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  std::string path = req.get_param_value("path");
  auto resolved = resolve_path(*session, path);
  if (resolved.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  if (!std::filesystem::exists(resolved)) {
    error_response(res, 404, "File not found");
    return;
  }

  if (std::filesystem::is_directory(resolved)) {
    error_response(res, 400, "Cannot download directory");
    return;
  }

  std::string filename = resolved.filename().string();

  // Check if encryption is enabled for this session
  bool decrypt = session->encryptionKey.has_value();

  if (decrypt) {
    // For encrypted files, we need to decrypt on the fly
    // Read and decrypt the file

    std::ifstream file(resolved, std::ios::binary);
    if (!file) {
      error_response(res, 500, "Failed to open file");
      return;
    }

    // Read header
    uint8_t header[crypto::HEADER_SIZE];
    file.read(reinterpret_cast<char*>(header), crypto::HEADER_SIZE);
    if (!file || file.gcount() < static_cast<std::streamsize>(crypto::HEADER_SIZE)) {
      // File is too small to be encrypted, serve as-is
      file.seekg(0);
      std::ostringstream ss;
      ss << file.rdbuf();
      set_cors_headers(res);
      res.set_header("Content-Disposition",
                     fmt::format("attachment; filename=\"{}\"", filename));
      res.set_content(ss.str(), get_mime_type(path));
      return;
    }

    // Parse header
    uint8_t file_id[crypto::FILE_ID_SIZE];
    uint16_t version;
    if (!crypto::parse_header(header, crypto::HEADER_SIZE, file_id, &version)) {
      // Not an encrypted file, serve as-is
      file.seekg(0);
      std::ostringstream ss;
      ss << file.rdbuf();
      set_cors_headers(res);
      res.set_header("Content-Disposition",
                     fmt::format("attachment; filename=\"{}\"", filename));
      res.set_content(ss.str(), get_mime_type(path));
      return;
    }

    // Decrypt all blocks
    std::string plaintext;
    std::vector<uint8_t> block_buf(crypto::ENCRYPTED_BLOCK_SIZE);
    uint8_t plaintext_buf[crypto::BLOCK_SIZE];

    while (file) {
      file.read(reinterpret_cast<char*>(block_buf.data()), crypto::ENCRYPTED_BLOCK_SIZE);
      auto bytes_read = file.gcount();
      if (bytes_read == 0) break;

      size_t plaintext_len = 0;
      if (!crypto::decrypt_block(block_buf.data(), static_cast<size_t>(bytes_read),
                                 session->encryptionKey->data(),
                                 plaintext_buf, &plaintext_len)) {
        error_response(res, 500, "Decryption failed");
        return;
      }

      plaintext.append(reinterpret_cast<char*>(plaintext_buf), plaintext_len);
    }

    set_cors_headers(res);
    res.set_header("Content-Disposition",
                   fmt::format("attachment; filename=\"{}\"", filename));
    res.set_content(plaintext, get_mime_type(path));

  } else {
    // No encryption, serve file directly
    std::ifstream file(resolved, std::ios::binary);
    if (!file) {
      error_response(res, 500, "Failed to open file");
      return;
    }

    std::ostringstream ss;
    ss << file.rdbuf();

    set_cors_headers(res);
    res.set_header("Content-Disposition",
                   fmt::format("attachment; filename=\"{}\"", filename));
    res.set_content(ss.str(), get_mime_type(path));
  }
}

// Handler: POST /api/fs/upload
static void handle_upload(const httplib::Request& req, httplib::Response& res) {
  auto* session = get_session(req);
  if (!session) {
    error_response(res, 401, "Not authenticated");
    return;
  }

  // Get the destination path from query param
  std::string dest_path = req.get_param_value("path");
  if (dest_path.empty()) {
    dest_path = "/";
  }

  auto resolved_dir = resolve_path(*session, dest_path);
  if (resolved_dir.empty()) {
    error_response(res, 403, "Access denied");
    return;
  }

  // Ensure destination directory exists
  if (!std::filesystem::exists(resolved_dir)) {
    std::error_code ec;
    std::filesystem::create_directories(resolved_dir, ec);
    if (ec) {
      error_response(res, 500, "Failed to create destination directory");
      return;
    }
  }

  // Check if this is multipart form data
  if (!req.has_file("file")) {
    error_response(res, 400, "No file uploaded");
    return;
  }

  const auto& file = req.get_file_value("file");
  std::string filename = file.filename;

  if (filename.empty()) {
    error_response(res, 400, "No filename provided");
    return;
  }

  // Sanitize filename
  if (filename.find('/') != std::string::npos || filename.find('\\') != std::string::npos) {
    // Extract just the filename part
    auto pos = filename.find_last_of("/\\");
    if (pos != std::string::npos) {
      filename = filename.substr(pos + 1);
    }
  }

  auto resolved_file = resolved_dir / filename;

  // Check if encryption is enabled for this session
  bool encrypt = session->encryptionKey.has_value();

  if (encrypt) {
    // Encrypt and write the file
    std::ofstream out(resolved_file, std::ios::binary);
    if (!out) {
      error_response(res, 500, "Failed to create file");
      return;
    }

    // Write header
    uint8_t header[crypto::HEADER_SIZE];
    crypto::create_header(header);
    out.write(reinterpret_cast<char*>(header), crypto::HEADER_SIZE);

    // Encrypt and write blocks
    const uint8_t* data = reinterpret_cast<const uint8_t*>(file.content.data());
    size_t remaining = file.content.size();
    size_t offset = 0;
    std::vector<uint8_t> ciphertext(crypto::ENCRYPTED_BLOCK_SIZE);

    while (remaining > 0) {
      size_t block_size = std::min(remaining, crypto::BLOCK_SIZE);

      if (!crypto::encrypt_block(data + offset, block_size,
                                 session->encryptionKey->data(),
                                 ciphertext.data())) {
        error_response(res, 500, "Encryption failed");
        return;
      }

      // Calculate actual ciphertext size
      size_t ciphertext_size = crypto::NONCE_SIZE + block_size + crypto::TAG_SIZE;
      out.write(reinterpret_cast<char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext_size));

      offset += block_size;
      remaining -= block_size;
    }

    out.close();
  } else {
    // No encryption, write directly
    std::ofstream out(resolved_file, std::ios::binary);
    if (!out) {
      error_response(res, 500, "Failed to create file");
      return;
    }

    out.write(file.content.data(), static_cast<std::streamsize>(file.content.size()));
    out.close();
  }

  json_response(res, 200, R"({"success":true})");
}

// Main server entry point
int start_http_server(const std::string& bind, uint16_t http_port, uint16_t rpc_port,
                      uint16_t auth_port, const std::string& root, const std::string& suffix,
                      const std::string& key_file, const std::string& cert_file,
                      const std::string& static_dir, bool skip_auth_server) {
  // Store global config
  g_root = root;
  g_suffix = suffix;
  g_rpc_port = rpc_port;
  g_auth_port = auth_port;

  // Start the auth RPC server so tokens can be registered via --authorize
  // Skip if running alongside RPC server (which already has its own auth server)
  if (!skip_auth_server) {
    start_auth_server_async(auth_port);
  }

  // Create server (with or without TLS)
  std::unique_ptr<httplib::Server> svr;

  if (!key_file.empty() && !cert_file.empty()) {
    auto ssl_svr = std::make_unique<httplib::SSLServer>(cert_file.c_str(), key_file.c_str());
    if (!ssl_svr->is_valid()) {
      std::cerr << "Failed to initialize HTTPS server with provided certificates" << std::endl;
      return 1;
    }
    svr = std::move(ssl_svr);
    std::cout << "HTTPS server starting on " << bind << ":" << http_port << std::endl;
  } else {
    svr = std::make_unique<httplib::Server>();
    std::cout << "HTTP server starting on " << bind << ":" << http_port << std::endl;
  }

  // CORS preflight
  svr->Options(R"(/api/.*)", handle_options);

  // Auth endpoints
  svr->Post("/api/auth/login", handle_login);
  svr->Post("/api/auth/logout", handle_logout);
  svr->Get("/api/auth/status", handle_auth_status);

  // File system endpoints
  svr->Get("/api/fs/list", handle_list);
  svr->Get("/api/fs/stat", handle_stat);
  svr->Post("/api/fs/mkdir", handle_mkdir);
  svr->Post("/api/fs/delete", handle_delete);
  svr->Delete("/api/fs/delete", handle_delete);
  svr->Post("/api/fs/rename", handle_rename);
  svr->Post("/api/fs/copy", handle_copy);

  // File transfer endpoints
  svr->Get("/api/fs/download", handle_download);
  svr->Post("/api/fs/upload", handle_upload);

  // ACME challenge endpoint for Let's Encrypt HTTP-01 validation
  svr->Get(R"(/\.well-known/acme-challenge/(.+))",
           [](const httplib::Request& req, httplib::Response& res) {
             std::string token = req.matches[1].str();

             std::string response;
             {
               std::lock_guard<std::mutex> lock(g_acme_mutex);
               if (g_acme_challenge_callback) {
                 response = g_acme_challenge_callback(token);
               }
             }

             if (!response.empty()) {
               res.set_content(response, "text/plain");
             } else {
               res.status = 404;
               res.set_content("Not found", "text/plain");
             }
           });

  // Serve static files if directory is provided
  std::string static_dir_copy = static_dir;  // Copy for lambda capture
  if (!static_dir.empty()) {
    if (!std::filesystem::exists(static_dir)) {
      std::cerr << "Warning: Static directory does not exist: " << static_dir << std::endl;
    } else {
      std::cout << "Serving static files from: " << static_dir << std::endl;

      // Mount the _app directory for JS/CSS bundles with proper MIME types
      auto ret = svr->set_mount_point("/_app", static_dir + "/_app");
      if (!ret) {
        std::cerr << "Warning: Failed to mount _app directory" << std::endl;
      }

      // Set file extension to MIME type mapping
      svr->set_file_extension_and_mimetype_mapping("js", "application/javascript");
      svr->set_file_extension_and_mimetype_mapping("mjs", "application/javascript");
      svr->set_file_extension_and_mimetype_mapping("css", "text/css");
      svr->set_file_extension_and_mimetype_mapping("json", "application/json");
      svr->set_file_extension_and_mimetype_mapping("svg", "image/svg+xml");
      svr->set_file_extension_and_mimetype_mapping("png", "image/png");
      svr->set_file_extension_and_mimetype_mapping("jpg", "image/jpeg");
      svr->set_file_extension_and_mimetype_mapping("jpeg", "image/jpeg");
      svr->set_file_extension_and_mimetype_mapping("woff", "font/woff");
      svr->set_file_extension_and_mimetype_mapping("woff2", "font/woff2");
    }
  }

  // Serve favicon
  svr->Get("/favicon.svg", [static_dir_copy](const httplib::Request&, httplib::Response& res) {
    std::string path = static_dir_copy + "/favicon.svg";
    if (std::filesystem::exists(path)) {
      std::ifstream file(path);
      if (file) {
        std::ostringstream ss;
        ss << file.rdbuf();
        res.set_content(ss.str(), "image/svg+xml");
        return;
      }
    }
    res.status = 404;
  });

  // Helper lambda to serve index.html for SPA routes
  auto serve_index = [static_dir_copy](const httplib::Request&, httplib::Response& res) {
    if (!static_dir_copy.empty()) {
      std::string index_path = static_dir_copy + "/index.html";
      if (std::filesystem::exists(index_path)) {
        std::ifstream file(index_path);
        if (file) {
          std::ostringstream ss;
          ss << file.rdbuf();
          res.set_content(ss.str(), "text/html");
          return;
        }
      }
    }
    res.status = 404;
    res.set_content("Not found", "text/plain");
  };

  // SPA routes - serve index.html for client-side routing
  svr->Get("/", serve_index);
  svr->Get("/browse", serve_index);
  svr->Get(R"(/browse/(.*))", serve_index);

  // Handle exceptions from handlers
  svr->set_exception_handler([](const httplib::Request& /*req*/, httplib::Response& res, std::exception_ptr ep) {
    set_cors_headers(res);
    res.status = 500;
    try {
      std::rethrow_exception(ep);
    } catch (const std::exception& e) {
      res.set_content(fmt::format(R"({{"success":false,"error":"{}"}})", e.what()), "application/json");
    } catch (...) {
      res.set_content(R"({"success":false,"error":"Unknown server error"})", "application/json");
    }
  });

  // Handle API 404s (only when no content has been set)
  svr->set_error_handler([](const httplib::Request& req, httplib::Response& res) {
    if (req.path.find("/api/") == 0 && res.body.empty()) {
      set_cors_headers(res);
      res.status = 404;
      res.set_content(R"({"success":false,"error":"API endpoint not found"})", "application/json");
    }
  });

  // Set payload limits
  svr->set_payload_max_length(1024 * 1024 * 100);  // 100MB max upload

  // Start server
  if (!svr->listen(bind.c_str(), http_port)) {
    std::cerr << "Failed to start HTTP server on " << bind << ":" << http_port << std::endl;
    return 1;
  }

  return 0;
}

}  // namespace ghostfs::http
