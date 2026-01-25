#include <ghostfs/uuid.h>

#ifdef USE_UUID_V4
#include <uuid_v4.h>

UUIDv4::UUIDGenerator<std::mt19937_64> uuidGenerator;

std::string gen_uuid() {
  UUIDv4::UUID uuid = uuidGenerator.getUUID();
  return uuid.str();
}

#else
// Cross-platform fallback for ARM and other non-x86 platforms
#include <random>
#include <sstream>
#include <iomanip>

std::string gen_uuid() {
  static thread_local std::mt19937_64 gen(std::random_device{}());
  static thread_local std::uniform_int_distribution<uint64_t> dist;

  uint64_t ab = dist(gen);
  uint64_t cd = dist(gen);

  // Set version 4 (random) and variant bits
  ab = (ab & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // version 4
  cd = (cd & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // variant 1

  std::ostringstream ss;
  ss << std::hex << std::setfill('0');
  ss << std::setw(8) << (ab >> 32);
  ss << '-';
  ss << std::setw(4) << ((ab >> 16) & 0xFFFF);
  ss << '-';
  ss << std::setw(4) << (ab & 0xFFFF);
  ss << '-';
  ss << std::setw(4) << (cd >> 48);
  ss << '-';
  ss << std::setw(12) << (cd & 0xFFFFFFFFFFFFULL);

  return ss.str();
}
#endif
