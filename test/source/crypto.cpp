#include <doctest/doctest.h>
#include <ghostfs/crypto.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>

using namespace ghostfs::crypto;

TEST_CASE("Crypto initialization") {
  CHECK(init() == true);
  // Should be safe to call multiple times
  CHECK(init() == true);
}

TEST_CASE("Size translation - empty file") {
  // Empty encrypted file has just a header
  CHECK(physical_to_logical_size(0) == 0);
  CHECK(physical_to_logical_size(HEADER_SIZE) == 0);

  CHECK(logical_to_physical_size(0) == HEADER_SIZE);
}

TEST_CASE("Size translation - single block") {
  // Single full block: header + nonce + ciphertext + tag
  int64_t physical_full_block = HEADER_SIZE + ENCRYPTED_BLOCK_SIZE;
  CHECK(physical_to_logical_size(physical_full_block) == BLOCK_SIZE);
  CHECK(logical_to_physical_size(BLOCK_SIZE) == physical_full_block);

  // Partial block (100 bytes plaintext)
  int64_t logical_partial = 100;
  int64_t physical_partial = HEADER_SIZE + NONCE_SIZE + logical_partial + TAG_SIZE;
  CHECK(logical_to_physical_size(logical_partial) == physical_partial);
  CHECK(physical_to_logical_size(physical_partial) == logical_partial);
}

TEST_CASE("Size translation - multiple blocks") {
  // Two full blocks
  int64_t logical_two = BLOCK_SIZE * 2;
  int64_t physical_two = HEADER_SIZE + ENCRYPTED_BLOCK_SIZE * 2;
  CHECK(logical_to_physical_size(logical_two) == physical_two);
  CHECK(physical_to_logical_size(physical_two) == logical_two);

  // 1.5 blocks (one full + half)
  int64_t logical_one_half = BLOCK_SIZE + BLOCK_SIZE / 2;
  int64_t physical_one_half = HEADER_SIZE + ENCRYPTED_BLOCK_SIZE + NONCE_SIZE + BLOCK_SIZE / 2 + TAG_SIZE;
  CHECK(logical_to_physical_size(logical_one_half) == physical_one_half);
  CHECK(physical_to_logical_size(physical_one_half) == logical_one_half);
}

TEST_CASE("Block number calculation") {
  CHECK(get_block_number(0) == 0);
  CHECK(get_block_number(100) == 0);
  CHECK(get_block_number(BLOCK_SIZE - 1) == 0);
  CHECK(get_block_number(BLOCK_SIZE) == 1);
  CHECK(get_block_number(BLOCK_SIZE + 1) == 1);
  CHECK(get_block_number(BLOCK_SIZE * 2) == 2);
}

TEST_CASE("Offset in block calculation") {
  CHECK(get_offset_in_block(0) == 0);
  CHECK(get_offset_in_block(100) == 100);
  CHECK(get_offset_in_block(BLOCK_SIZE - 1) == BLOCK_SIZE - 1);
  CHECK(get_offset_in_block(BLOCK_SIZE) == 0);
  CHECK(get_offset_in_block(BLOCK_SIZE + 100) == 100);
}

TEST_CASE("Encrypt and decrypt block - full block") {
  REQUIRE(init());

  uint8_t key[KEY_SIZE];
  std::memset(key, 0x42, KEY_SIZE);  // Test key

  uint8_t plaintext[BLOCK_SIZE];
  for (size_t i = 0; i < BLOCK_SIZE; i++) {
    plaintext[i] = static_cast<uint8_t>(i & 0xFF);
  }

  uint8_t ciphertext[ENCRYPTED_BLOCK_SIZE];
  REQUIRE(encrypt_block(plaintext, BLOCK_SIZE, key, ciphertext));

  // Verify ciphertext is different from plaintext
  CHECK(std::memcmp(ciphertext + NONCE_SIZE, plaintext, BLOCK_SIZE) != 0);

  // Decrypt
  uint8_t decrypted[BLOCK_SIZE];
  size_t decrypted_len;
  REQUIRE(decrypt_block(ciphertext, NONCE_SIZE + BLOCK_SIZE + TAG_SIZE, key, decrypted, &decrypted_len));

  CHECK(decrypted_len == BLOCK_SIZE);
  CHECK(std::memcmp(plaintext, decrypted, BLOCK_SIZE) == 0);
}

TEST_CASE("Encrypt and decrypt block - partial block") {
  REQUIRE(init());

  uint8_t key[KEY_SIZE];
  std::memset(key, 0x42, KEY_SIZE);

  const size_t partial_size = 100;
  uint8_t plaintext[partial_size];
  for (size_t i = 0; i < partial_size; i++) {
    plaintext[i] = static_cast<uint8_t>(i);
  }

  uint8_t ciphertext[ENCRYPTED_BLOCK_SIZE];
  REQUIRE(encrypt_block(plaintext, partial_size, key, ciphertext));

  uint8_t decrypted[BLOCK_SIZE];
  size_t decrypted_len;
  REQUIRE(decrypt_block(ciphertext, NONCE_SIZE + partial_size + TAG_SIZE, key, decrypted, &decrypted_len));

  CHECK(decrypted_len == partial_size);
  CHECK(std::memcmp(plaintext, decrypted, partial_size) == 0);
}

TEST_CASE("Decrypt with wrong key fails") {
  REQUIRE(init());

  uint8_t key1[KEY_SIZE];
  uint8_t key2[KEY_SIZE];
  std::memset(key1, 0x42, KEY_SIZE);
  std::memset(key2, 0x43, KEY_SIZE);  // Different key

  uint8_t plaintext[] = "secret data";
  size_t len = sizeof(plaintext);

  uint8_t ciphertext[ENCRYPTED_BLOCK_SIZE];
  REQUIRE(encrypt_block(plaintext, len, key1, ciphertext));

  // Try to decrypt with wrong key
  uint8_t decrypted[BLOCK_SIZE];
  size_t decrypted_len;
  CHECK(decrypt_block(ciphertext, NONCE_SIZE + len + TAG_SIZE, key2, decrypted, &decrypted_len) == false);
}

TEST_CASE("Decrypt with tampered ciphertext fails") {
  REQUIRE(init());

  uint8_t key[KEY_SIZE];
  std::memset(key, 0x42, KEY_SIZE);

  uint8_t plaintext[] = "secret data";
  size_t len = sizeof(plaintext);

  uint8_t ciphertext[ENCRYPTED_BLOCK_SIZE];
  REQUIRE(encrypt_block(plaintext, len, key, ciphertext));

  // Tamper with ciphertext
  ciphertext[NONCE_SIZE + 5] ^= 0xFF;

  uint8_t decrypted[BLOCK_SIZE];
  size_t decrypted_len;
  CHECK(decrypt_block(ciphertext, NONCE_SIZE + len + TAG_SIZE, key, decrypted, &decrypted_len) == false);
}

TEST_CASE("Header creation and parsing") {
  REQUIRE(init());

  uint8_t header[HEADER_SIZE];
  create_header(header);

  // Check version
  uint16_t version = (static_cast<uint16_t>(header[0]) << 8) | header[1];
  CHECK(version == CRYPTO_VERSION);

  // Parse header
  uint8_t file_id[FILE_ID_SIZE];
  uint16_t parsed_version;
  REQUIRE(parse_header(header, HEADER_SIZE, file_id, &parsed_version));

  CHECK(parsed_version == CRYPTO_VERSION);
  CHECK(std::memcmp(file_id, header + 2, FILE_ID_SIZE) == 0);
}

TEST_CASE("Header parsing rejects invalid version") {
  uint8_t header[HEADER_SIZE];
  header[0] = 0xFF;  // Invalid version
  header[1] = 0xFF;

  uint8_t file_id[FILE_ID_SIZE];
  uint16_t version;
  CHECK(parse_header(header, HEADER_SIZE, file_id, &version) == false);
}

TEST_CASE("Header parsing rejects short header") {
  uint8_t header[HEADER_SIZE - 1];
  uint8_t file_id[FILE_ID_SIZE];
  uint16_t version;
  CHECK(parse_header(header, HEADER_SIZE - 1, file_id, &version) == false);
}

TEST_CASE("Key file generation and loading") {
  REQUIRE(init());

  std::string key_path = "/tmp/ghostfs_test_key_" + std::to_string(getpid());

  // Generate key
  REQUIRE(generate_key_file(key_path));

  // Check file exists and has correct size
  std::ifstream file(key_path, std::ios::binary | std::ios::ate);
  REQUIRE(file.is_open());
  CHECK(file.tellg() == KEY_SIZE);
  file.close();

  // Load key
  uint8_t key[KEY_SIZE];
  REQUIRE(load_key_file(key_path, key));

  // Key should not be all zeros
  bool all_zero = true;
  for (size_t i = 0; i < KEY_SIZE; i++) {
    if (key[i] != 0) {
      all_zero = false;
      break;
    }
  }
  CHECK(all_zero == false);

  // Cleanup
  std::filesystem::remove(key_path);
}

TEST_CASE("Load nonexistent key file fails") {
  uint8_t key[KEY_SIZE];
  CHECK(load_key_file("/nonexistent/path/key.bin", key) == false);
}

TEST_CASE("Unique nonces per encryption") {
  REQUIRE(init());

  uint8_t key[KEY_SIZE];
  std::memset(key, 0x42, KEY_SIZE);

  uint8_t plaintext[] = "same data";
  size_t len = sizeof(plaintext);

  uint8_t ciphertext1[ENCRYPTED_BLOCK_SIZE];
  uint8_t ciphertext2[ENCRYPTED_BLOCK_SIZE];

  REQUIRE(encrypt_block(plaintext, len, key, ciphertext1));
  REQUIRE(encrypt_block(plaintext, len, key, ciphertext2));

  // Nonces should be different (first 24 bytes)
  CHECK(std::memcmp(ciphertext1, ciphertext2, NONCE_SIZE) != 0);

  // Ciphertexts should be different (due to different nonces)
  CHECK(std::memcmp(ciphertext1, ciphertext2, NONCE_SIZE + len + TAG_SIZE) != 0);
}
