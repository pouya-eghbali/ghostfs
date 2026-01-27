#include <doctest/doctest.h>
#include <ghostfs/ghostfs.h>
#include <ghostfs/version.h>

#include <string>

TEST_CASE("GhostFS version") {
  static_assert(std::string_view(GHOSTFS_VERSION) == std::string_view("1.1.0"));
  CHECK(std::string(GHOSTFS_VERSION) == std::string("1.1.0"));
}
