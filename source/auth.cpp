#include <ghostfs/uuid.h>

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <map>
#include <string>

struct User {
  std::string sub_directory;
  std::map<std::string, std::string> soft_mounts;
};

struct Token {
  std::string user;
  int64_t usable;
  bool has_active_session;  // Track if user has an active session with this token
};

std::map<std::string, struct User> users;
std::map<std::string, struct Token> tokens;

std::string random_token() {
  std::string uuid = gen_uuid();
  std::replace(uuid.begin(), uuid.end(), '-', uuid[3]);
  return uuid;
}

std::string add_token(std::string user, std::string token, int64_t retries) {
  std::string token_to_add = token.length() ? token : random_token();

  tokens[token_to_add] = {.user = user, .usable = retries, .has_active_session = false};

  if (not users.contains(user)) {
    users[user] = {.sub_directory = user, .soft_mounts = {}};
  }

  return token_to_add;
}

void soft_mount(std::string user, std::string src, std::string dest) {
  if (users.contains(user)) {
    users[user].soft_mounts[dest] = src;
  }
}

void soft_unmount(std::string user, std::string dest) {
  if (users.contains(user) and users[user].soft_mounts.contains(dest)) {
    users[user].soft_mounts.erase(dest);
  }
}

void soft_unmount(std::string user) {
  if (users.contains(user)) {
    users[user].soft_mounts.clear();
  }
}

std::map<std::string, std::string>* get_user_mounts(std::string user) {
  return &users[user].soft_mounts;
}

bool authenticate(std::string token, std::string user) {
  if (not tokens.contains(token)) {
    return false;
  }

  struct Token* t = &tokens[token];

  if (t->user != user) {
    return false;
  }

  if (t->usable == 0) {
    return false;
  } else if (t->usable > 0) {
    // Don't decrement for re-authentication with an active session
    // This allows multi-threaded FUSE clients to create multiple connections
    if (!t->has_active_session) {
      t->usable--;
      t->has_active_session = true;
    }
  } else {
    // usable == -1 means infinite use
    t->has_active_session = true;
  }

  return true;
}

std::filesystem::path normalize_path(std::string root, std::string user_id) {
  return std::filesystem::path(root) / users[user_id].sub_directory;
}

std::filesystem::path normalize_path(std::string root, std::string user_id, std::string path) {
  if (!path.length()) {
    return normalize_path(root, user_id);
  }
  return std::filesystem::path(root) / users[user_id].sub_directory / path;
}

bool is_subpath(const std::filesystem::path& root, const std::filesystem::path& path) {
  const auto mismatch_pair = std::mismatch(path.begin(), path.end(), root.begin(), root.end());
  return mismatch_pair.second == root.end();
}

bool check_exists(std::filesystem::path path) {
  std::error_code ec;
  // Use symlink_status to avoid following symlinks, which could cause
  // re-entry deadlocks if the symlink points back to a FUSE mount
  auto status = std::filesystem::symlink_status(path, ec);
  return std::filesystem::exists(status);
}

bool check_access(std::string root, std::string user_id, std::string suffix, std::string path) {
  std::filesystem::path user_root = normalize_path(root, user_id, suffix);

  auto const root_can = user_root.lexically_normal();
  auto const path_can = std::filesystem::path(path).lexically_normal();

  if (not check_exists(path_can)) {
    return true;
  }

  if (root_can == path_can) {
    return true;
  }

  if (is_subpath(root_can, path_can)) {
    return true;
  };

  for ([[maybe_unused]] auto const& mount : *get_user_mounts(user_id)) {
    std::string source = mount.second;
    // Use lexically_normal instead of canonical to avoid following symlinks,
    // which could cause re-entry deadlocks
    auto const source_can = std::filesystem::path(source).lexically_normal();

    if (is_subpath(source_can, path_can)) {
      return true;
    };
  }

  return false;
}
