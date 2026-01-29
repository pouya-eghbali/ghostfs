#include <ghostfs/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <fstream>
#include <iostream>

namespace ghostfs::crypto {

  // Thread-local EVP contexts for reuse (avoids allocation per operation)
  namespace {
    thread_local EVP_CIPHER_CTX* tl_encrypt_ctx = nullptr;
    thread_local EVP_CIPHER_CTX* tl_decrypt_ctx = nullptr;

    EVP_CIPHER_CTX* get_encrypt_ctx() {
      if (!tl_encrypt_ctx) {
        tl_encrypt_ctx = EVP_CIPHER_CTX_new();
      }
      return tl_encrypt_ctx;
    }

    EVP_CIPHER_CTX* get_decrypt_ctx() {
      if (!tl_decrypt_ctx) {
        tl_decrypt_ctx = EVP_CIPHER_CTX_new();
      }
      return tl_decrypt_ctx;
    }
  }  // anonymous namespace

  bool init() {
    // OpenSSL 1.1+ auto-initializes
    return true;
  }

  int64_t physical_to_logical_size(int64_t physical_size) {
    if (physical_size <= static_cast<int64_t>(HEADER_SIZE)) {
      return 0;
    }

    int64_t data_size = physical_size - HEADER_SIZE;
    int64_t full_blocks = data_size / ENCRYPTED_BLOCK_SIZE;
    int64_t remainder = data_size % ENCRYPTED_BLOCK_SIZE;

    int64_t logical_size = full_blocks * BLOCK_SIZE;

    // Handle partial last block
    if (remainder > static_cast<int64_t>(NONCE_SIZE + TAG_SIZE)) {
      logical_size += remainder - static_cast<int64_t>(NONCE_SIZE + TAG_SIZE);
    }

    return logical_size;
  }

  int64_t logical_to_physical_size(int64_t logical_size) {
    if (logical_size <= 0) {
      return HEADER_SIZE;
    }

    int64_t full_blocks = logical_size / BLOCK_SIZE;
    int64_t remainder = logical_size % BLOCK_SIZE;

    int64_t physical_size = HEADER_SIZE + full_blocks * ENCRYPTED_BLOCK_SIZE;

    // Handle partial last block
    if (remainder > 0) {
      physical_size += NONCE_SIZE + remainder + TAG_SIZE;
    }

    return physical_size;
  }

  int64_t logical_to_physical_offset(int64_t logical_offset) {
    size_t block_num = get_block_number(logical_offset);
    size_t offset_in_block = get_offset_in_block(logical_offset);

    // Physical offset = header + (block_num * encrypted_block_size) + nonce + offset_in_ciphertext
    return HEADER_SIZE + block_num * ENCRYPTED_BLOCK_SIZE + NONCE_SIZE + offset_in_block;
  }

  size_t get_block_number(int64_t logical_offset) {
    return static_cast<size_t>(logical_offset / BLOCK_SIZE);
  }

  size_t get_offset_in_block(int64_t logical_offset) {
    return static_cast<size_t>(logical_offset % BLOCK_SIZE);
  }

  bool encrypt_block(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* key,
                     uint8_t* ciphertext_out) {
    if (plaintext_len > BLOCK_SIZE) {
      return false;
    }

    // Generate random nonce (IV)
    uint8_t* nonce = ciphertext_out;
    if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
      return false;
    }

    // Use thread-local context (reused instead of allocated per call)
    EVP_CIPHER_CTX* ctx = get_encrypt_ctx();
    if (!ctx) {
      return false;
    }

    // Reset context for reuse
    EVP_CIPHER_CTX_reset(ctx);

    uint8_t* ciphertext = ciphertext_out + NONCE_SIZE;
    int len = 0;
    int ciphertext_len = 0;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      return false;
    }

    // Set IV length (12 bytes is default for GCM, but be explicit)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
      return false;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
      return false;
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, static_cast<int>(plaintext_len)) != 1) {
      return false;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
      return false;
    }
    ciphertext_len += len;

    // Get the authentication tag (appended after ciphertext)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ciphertext + ciphertext_len)
        != 1) {
      return false;
    }

    return true;
  }

  bool decrypt_block(const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* key,
                     uint8_t* plaintext_out, size_t* plaintext_len) {
    if (ciphertext_len < NONCE_SIZE + TAG_SIZE) {
      return false;
    }

    const uint8_t* nonce = ciphertext;
    const uint8_t* encrypted_data = ciphertext + NONCE_SIZE;
    size_t encrypted_len = ciphertext_len - NONCE_SIZE - TAG_SIZE;
    const uint8_t* tag = ciphertext + ciphertext_len - TAG_SIZE;

    // Use thread-local context (reused instead of allocated per call)
    EVP_CIPHER_CTX* ctx = get_decrypt_ctx();
    if (!ctx) {
      return false;
    }

    // Reset context for reuse
    EVP_CIPHER_CTX_reset(ctx);

    int len = 0;
    int total_len = 0;

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      return false;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
      return false;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
      return false;
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext_out, &len, encrypted_data, static_cast<int>(encrypted_len))
        != 1) {
      return false;
    }
    total_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, const_cast<uint8_t*>(tag)) != 1) {
      return false;
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len) != 1) {
      // Authentication failed
      return false;
    }
    total_len += len;

    *plaintext_len = static_cast<size_t>(total_len);
    return true;
  }

  void create_header(uint8_t* header_out) {
    // Write version (big-endian)
    header_out[0] = (CRYPTO_VERSION >> 8) & 0xFF;
    header_out[1] = CRYPTO_VERSION & 0xFF;

    // Generate random file_id
    RAND_bytes(header_out + 2, FILE_ID_SIZE);
  }

  bool parse_header(const uint8_t* header, size_t header_len, uint8_t* file_id_out,
                    uint16_t* version_out) {
    if (header_len < HEADER_SIZE) {
      return false;
    }

    // Read version (big-endian)
    uint16_t version = (static_cast<uint16_t>(header[0]) << 8) | header[1];

    if (version != CRYPTO_VERSION) {
      std::cerr << "Unsupported encryption version: " << version << std::endl;
      return false;
    }

    if (version_out) {
      *version_out = version;
    }

    if (file_id_out) {
      std::memcpy(file_id_out, header + 2, FILE_ID_SIZE);
    }

    return true;
  }

  bool generate_key_file(const std::string& path) {
    uint8_t key[KEY_SIZE];
    if (RAND_bytes(key, KEY_SIZE) != 1) {
      std::cerr << "Failed to generate random key" << std::endl;
      return false;
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
      std::cerr << "Failed to create key file: " << path << std::endl;
      return false;
    }

    file.write(reinterpret_cast<const char*>(key), KEY_SIZE);
    file.close();

    // Secure erase the key from stack
    OPENSSL_cleanse(key, KEY_SIZE);

    return true;
  }

  bool load_key_file(const std::string& path, uint8_t* key_out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
      std::cerr << "Failed to open key file: " << path << std::endl;
      return false;
    }

    auto size = file.tellg();
    if (size != KEY_SIZE) {
      std::cerr << "Invalid key file size: expected " << KEY_SIZE << " bytes, got " << size
                << std::endl;
      return false;
    }

    file.seekg(0);
    file.read(reinterpret_cast<char*>(key_out), KEY_SIZE);

    return true;
  }

}  // namespace ghostfs::crypto
