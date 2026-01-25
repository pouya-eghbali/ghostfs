cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# ---- Project ----

# Note: update this to your new project's name and version
project(
  GhostFS
  VERSION 1.0
  LANGUAGES CXX
)

# ---- Include guards ----
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
    "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
  )
endif()

# ---- Add dependencies via CPM ----
# see https://github.com/TheLartians/CPM.cmake for more info
include(cmake/CPM.cmake)

# ---- Add OpenSSL ----
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

message("OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")

# PackageProject.cmake will be used to make our target installable
CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.8.0")

# Only use uuid_v4 on x86 platforms (it requires SSE/AVX)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686")
  CPMAddPackage(
    NAME uuid_v4
    VERSION 1.0.0
    GITHUB_REPOSITORY crashoz/uuid_v4
  )
  set(USE_UUID_V4 ON)
else()
  set(USE_UUID_V4 OFF)
endif()

CPMAddPackage(
  NAME capnproto
  VERSION 1.3.0
  GITHUB_REPOSITORY capnproto/capnproto
  OPTIONS "WITH_OPENSSL ON" "BUILD_TESTING OFF"
  #OPTIONS "WITH_OPENSSL ON" "BUILD_TESTING OFF" "CMAKE_BUILD_TYPE Debug"
)

CPMAddPackage(
  NAME fmt
  GIT_TAG 12.1.0
  GITHUB_REPOSITORY fmtlib/fmt
  OPTIONS "FMT_INSTALL YES" # create an installable target
)

# ---- Build type ----
# set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE RelWithDebInfo)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific warning flags
if(MSVC)
  # MSVC warning flags
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
else()
  # GCC/Clang warning flags
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb")
endif()

if(NOT MSVC)
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
endif()

# ---- Add platform-specific filesystem dependencies ----
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake")

if(WIN32)
  # Windows: Use WinFSP
  find_package(WinFSP REQUIRED)
  add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
  include_directories(${WINFSP_INCLUDE_DIR})
  set(PLATFORM_FS_LIBS ${WINFSP_LIBRARY})
else()
  # Linux/macOS: Use FUSE
  find_package(FUSE REQUIRED)
  add_definitions(-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29)
  include_directories(${FUSE_INCLUDE_DIR})
  set(PLATFORM_FS_LIBS ${FUSE_LIBRARIES})
endif()

# ---- Add source files ----

# Note: globbing sources is considered bad practice as CMake's generators may not detect new files
# automatically. Keep that in mind when changing files, or explicitly mention them here.
file(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

# Platform-specific source files
if(WIN32)
  set(PLATFORM_FS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/source/fs_winfsp.cpp")
else()
  set(PLATFORM_FS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/source/fs_fuse.cpp")
endif()

# Common source files (excluding platform-specific fs implementations)
set(sources
  "${CMAKE_CURRENT_SOURCE_DIR}/source/fs_common.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/source/rpc.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/source/auth.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/source/uuid.cpp"
  ${PLATFORM_FS_SOURCE}
)

file(GLOB_RECURSE capnp_headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/capnp/*.h")
file(GLOB_RECURSE capnp_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/capnp/*.c++")

# ---- Create library ----

# Note: for header-only libraries change all PUBLIC flags to INTERFACE and create an interface
# target: add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME} ${capnp_headers} ${capnp_sources} ${headers} ${sources})

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)

# being a cross-platform target, we enforce standards conformance on MSVC
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/permissive->")

# enable avx2 on x86 platforms only
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686")
  target_compile_options(${PROJECT_NAME} PUBLIC "-mavx2")
endif()

# Link dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)
target_link_libraries(${PROJECT_NAME} PRIVATE CapnProto::capnp)
target_link_libraries(${PROJECT_NAME} PRIVATE CapnProto::capnp-rpc)
target_link_libraries(${PROJECT_NAME} PRIVATE CapnProto::kj-tls)
target_link_libraries(${PROJECT_NAME} PUBLIC ${PLATFORM_FS_LIBS})

# uuid_v4 include only on x86
if(USE_UUID_V4)
  target_include_directories(
    ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${uuid_v4_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  )
  target_compile_definitions(${PROJECT_NAME} PRIVATE USE_UUID_V4)
endif()

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/capnp>
  $<INSTALL_INTERFACE:capnp/${PROJECT_NAME}-${PROJECT_VERSION}>
)

if(WIN32)
  target_include_directories(
    ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${WINFSP_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  )
else()
  target_include_directories(
    ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${FUSE_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  )
endif()

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

# ---- Create an installable target ----
# this allows users to install and find the library via `find_package()`.

# the location where the project's version header will be placed should match the project's regular
# header paths
string(TOLOWER ${PROJECT_NAME}/version.h VERSION_HEADER_LOCATION)

packageProject(
  NAME ${PROJECT_NAME}
  VERSION ${PROJECT_VERSION}
  NAMESPACE ${PROJECT_NAME}
  BINARY_DIR ${PROJECT_BINARY_DIR}
  INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
  INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
  VERSION_HEADER "${VERSION_HEADER_LOCATION}"
  COMPATIBILITY SameMajorVersion
  DEPENDENCIES "fmt 12.1.0"
)
