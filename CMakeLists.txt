cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# ---- Project ----

# Note: update this to your new project's name and version
project(
  GhostFS
  VERSION 1.0
  LANGUAGES CXX
)

# ---- Options ----
option(GHOSTFS_CSI_SUPPORT "Enable CSI driver support (requires gRPC, Linux only)" OFF)

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

# ---- CSI Support (optional, requires gRPC) ----
if(GHOSTFS_CSI_SUPPORT)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(WARNING "CSI support is only available on Linux. Disabling GHOSTFS_CSI_SUPPORT.")
    set(GHOSTFS_CSI_SUPPORT OFF)
  else()
    find_package(Protobuf REQUIRED)
    find_package(gRPC REQUIRED)

    # Generate protobuf and gRPC files from csi.proto
    set(CSI_PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/csi/csi.proto")
    set(CSI_PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/csi_proto")
    file(MAKE_DIRECTORY ${CSI_PROTO_OUT_DIR})

    set(CSI_PROTO_SRCS "${CSI_PROTO_OUT_DIR}/csi.pb.cc")
    set(CSI_PROTO_HDRS "${CSI_PROTO_OUT_DIR}/csi.pb.h")
    set(CSI_GRPC_SRCS "${CSI_PROTO_OUT_DIR}/csi.grpc.pb.cc")
    set(CSI_GRPC_HDRS "${CSI_PROTO_OUT_DIR}/csi.grpc.pb.h")

    # Find protoc and grpc_cpp_plugin
    find_program(PROTOC_EXECUTABLE protoc REQUIRED)
    find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

    add_custom_command(
      OUTPUT ${CSI_PROTO_SRCS} ${CSI_PROTO_HDRS} ${CSI_GRPC_SRCS} ${CSI_GRPC_HDRS}
      COMMAND ${PROTOC_EXECUTABLE}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/csi
        --cpp_out=${CSI_PROTO_OUT_DIR}
        --grpc_out=${CSI_PROTO_OUT_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
        ${CSI_PROTO_FILE}
      DEPENDS ${CSI_PROTO_FILE}
      COMMENT "Generating CSI protobuf and gRPC files"
    )
  endif()
endif()

# ---- Build type ----
# set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE RelWithDebInfo)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

# ---- Add FUSE dependencies ----
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(FUSE REQUIRED)
add_definitions(-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29)
include_directories(${FUSE_INCLUDE_DIR})

# ---- Add source files ----

# Note: globbing sources is considered bad practice as CMake's generators may not detect new files
# automatically. Keep that in mind when changing files, or explicitly mention them here.
file(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

# Exclude csi.cpp if CSI support is not enabled (it won't compile without gRPC)
if(NOT GHOSTFS_CSI_SUPPORT)
  list(FILTER sources EXCLUDE REGEX ".*csi\\.cpp$")
endif()

file(GLOB_RECURSE capnp_headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/capnp/*.h")
file(GLOB_RECURSE capnp_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/capnp/*.c++")

# ---- Create library ----

# Note: for header-only libraries change all PUBLIC flags to INTERFACE and create an interface
# target: add_library(${PROJECT_NAME} INTERFACE)
if(GHOSTFS_CSI_SUPPORT)
  # Include generated CSI proto sources directly in the library
  add_library(${PROJECT_NAME} ${capnp_headers} ${capnp_sources} ${headers} ${sources} ${CSI_PROTO_SRCS} ${CSI_GRPC_SRCS})
else()
  add_library(${PROJECT_NAME} ${capnp_headers} ${capnp_sources} ${headers} ${sources})
endif()

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
target_link_libraries(${PROJECT_NAME} PUBLIC ${FUSE_LIBRARIES})

# uuid_v4 include only on x86
if(USE_UUID_V4)
  target_include_directories(
    ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${uuid_v4_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  )
  target_compile_definitions(${PROJECT_NAME} PRIVATE USE_UUID_V4)
endif()

# CSI support
if(GHOSTFS_CSI_SUPPORT)
  target_compile_definitions(${PROJECT_NAME} PRIVATE GHOSTFS_CSI_SUPPORT)
  target_link_libraries(${PROJECT_NAME} PRIVATE protobuf::libprotobuf gRPC::grpc++)
  target_include_directories(${PROJECT_NAME} PRIVATE ${CSI_PROTO_OUT_DIR})
endif()

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/capnp>
  $<INSTALL_INTERFACE:capnp/${PROJECT_NAME}-${PROJECT_VERSION}>
)

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${FUSE_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

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
