#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace ghostfs::crypto {

// File format version
constexpr uint16_t CRYPTO_VERSION = 0x0001;

// Size constants
constexpr size_t FILE_ID_SIZE = 16;      // Random file identifier in header
constexpr size_t HEADER_SIZE = 18;       // 2 bytes version + 16 bytes file_id
constexpr size_t BLOCK_SIZE = 131072;    // 128KB plaintext block size
constexpr size_t NONCE_SIZE = 12;        // AES-256-GCM nonce (IV)
constexpr size_t TAG_SIZE = 16;          // GCM authentication tag
constexpr size_t KEY_SIZE = 32;          // 256-bit key

// Each encrypted block: nonce (12) + ciphertext (64KB) + tag (16) = 65564 bytes
constexpr size_t ENCRYPTED_BLOCK_SIZE = NONCE_SIZE + BLOCK_SIZE + TAG_SIZE;

// Per-file encryption context (cached while file is open)
struct FileContext {
  uint8_t file_id[FILE_ID_SIZE];
  bool is_encrypted;
  int64_t plaintext_size;  // Cached logical size
};

// Initialize libsodium (call once at startup)
bool init();

// Offset/size translation between logical (plaintext) and physical (ciphertext) space
int64_t physical_to_logical_size(int64_t physical_size);
int64_t logical_to_physical_size(int64_t logical_size);
int64_t logical_to_physical_offset(int64_t logical_offset);
size_t get_block_number(int64_t logical_offset);
size_t get_offset_in_block(int64_t logical_offset);

// Block encryption/decryption
// encrypt_block: encrypts plaintext into ciphertext_out (must be ENCRYPTED_BLOCK_SIZE bytes)
//                generates random nonce, stores nonce + ciphertext + tag
// Returns true on success
bool encrypt_block(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* key,
                   uint8_t* ciphertext_out);

// decrypt_block: decrypts ciphertext (ENCRYPTED_BLOCK_SIZE bytes) into plaintext_out
//                reads nonce from ciphertext, verifies tag
// Returns true on success, false if authentication fails
bool decrypt_block(const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* key,
                   uint8_t* plaintext_out, size_t* plaintext_len);

// Header operations
void create_header(uint8_t* header_out);  // Generates random file_id, writes version + file_id
bool parse_header(const uint8_t* header, size_t header_len, uint8_t* file_id_out,
                  uint16_t* version_out);

// Key management
bool generate_key_file(const std::string& path);
bool load_key_file(const std::string& path, uint8_t* key_out);

}  // namespace ghostfs::crypto
