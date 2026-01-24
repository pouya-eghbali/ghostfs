# CLAUDE.md - GhostFS Development Guide

## Project Overview

GhostFS is a FUSE-based distributed filesystem that serves any filesystem over the network using Cap'n Proto RPC. It consists of a FUSE client that mounts remote filesystems locally and a server that exposes local filesystem operations over the network.

**Version:** 1.0
**License:** Business Source License (BSL) 1.1 (changes to AGPL v3.0 ten years after each version's release)
**Licensor:** Pouya Eghbali
**Usage:** Free for self-hosted, non-commercial use (including personal and research). See ghostfs.io for commercial licensing.

## Architecture

```
┌─────────────────┐     Cap'n Proto RPC      ┌─────────────────┐
│   FUSE Client   │ ◄──────────────────────► │   RPC Server    │
│   (fs.cpp)      │       (TLS optional)     │   (rpc.cpp)     │
└─────────────────┘                          └─────────────────┘
        │                                            │
        ▼                                            ▼
   Local Mount                               Backend Filesystem
```

### Key Components

| Component | Files | Purpose |
|-----------|-------|---------|
| FUSE Client | `source/fs.cpp`, `include/ghostfs/fs.h` | Low-level FUSE operations, caching |
| RPC Server | `source/rpc.cpp`, `include/ghostfs/rpc.h` | Cap'n Proto server, filesystem backend |
| Auth System | `source/auth.cpp`, `include/ghostfs/auth.h` | Token-based auth, soft mounts, access control |
| Protocol | `capnp/*.capnp` | 41 Cap'n Proto schema files for RPC |
| CLI | `standalone/source/main.cpp` | Command-line interface for client/server |

## Build Instructions

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libfuse-dev zlib1g-dev cmake g++

# macOS
brew install osxfuse cmake
```

### Building

```bash
# Build standalone executable (recommended)
cmake -S standalone -B build/standalone
cmake --build build/standalone -j$(nproc)

# Build with tests
cmake -S all -B build/all
cmake --build build/all -j$(nproc)

# Run tests
ctest --test-dir build/all
```

The output binary is `build/standalone/GhostFS`.

## Running

### Server Mode

```bash
./GhostFS --server --root ~/.ghostfs/root --bind 0.0.0.0 --port 3444
```

### Client Mode

```bash
./GhostFS --client --host <server-ip> --port 3444 --user <username> --token <token> /mount/point
```

### Key CLI Options

- `--server/-s`: Run as RPC server
- `--client/-c`: Run as FUSE client
- `--authorize/-A`: Run as auth server
- `--bind/-b`: Server bind address (default: 127.0.0.1)
- `--host/-H`: Server hostname for client (default: 127.0.0.1)
- `--port/-p`: Server port (default: 3444)
- `--root/-r`: Server root directory (default: ~/.ghostfs/root)
- `--user/-u`: Username for client connection
- `--token/-t`: Authentication token
- `--write-back/-w`: Write cache size (default: 8)
- `--read-ahead/-C`: Read cache size (default: 8)
- `--key/-k`, `--cert/-T`: TLS key and certificate files

## Code Organization

```
ghostfs/
├── source/              # Core library implementation
│   ├── fs.cpp           # FUSE client (1504 lines)
│   ├── rpc.cpp          # RPC server (1693 lines)
│   ├── auth.cpp         # Authentication system
│   └── uuid.cpp         # UUID generation
├── include/ghostfs/     # Public headers
├── capnp/               # Protocol definitions (41 files)
├── standalone/          # CLI executable
├── test/                # Unit tests (doctest)
├── cmake/               # CMake utilities
└── documentation/       # Doxygen/Sphinx docs
```

## Development Guidelines

### C++ Standards

- **C++ Standard:** C++20
- **Compiler flags:** `-Wall -Wextra -mavx2`
- Namespace: `ghostfs`

### Dependencies (managed via CPM)

- FUSE 2.9+ - Filesystem interface
- Cap'n Proto 0.10.4 - RPC and serialization
- fmt 7.1.3 - String formatting
- uuid_v4 1.0.0 - UUID generation
- OpenSSL - TLS support
- doctest 2.4.5 - Testing (optional)
- cxxopts 2.2.1 - CLI parsing (optional)

### Key Patterns

1. **Inode Management:** `ino_to_path` and `path_to_ino` maps in fs.cpp maintain inode-to-path mappings
2. **Caching:** Write-back cache (batches writes) and read-ahead cache (prefetches reads)
3. **File Handles:** Server tracks valid handles in `fh_set`
4. **Auth:** Token-based with retry limits; per-user subdirectories for isolation
5. **Soft Mounts:** Virtual mount points extending user-accessible paths

### Adding New RPC Methods

1. Create request/response `.capnp` files in `capnp/`
2. Add method to `GhostFS` interface in `capnp/ghostfs.capnp`
3. Implement server handler in `source/rpc.cpp`
4. Implement client call in `source/fs.cpp`

### Security Considerations

- All paths are canonicalized to prevent directory traversal
- Access checks performed on every operation via `check_access()`
- Token authentication required for all client connections
- TLS supported for encrypted transport

## Testing

```bash
# Build and run tests
cmake -S test -B build/test
cmake --build build/test
ctest --test-dir build/test
```

Tests use doctest framework. Test files are in `test/source/`.

## Common Tasks

### Debugging FUSE Operations

Enable FUSE debug output with `-o debug` in mount options.

### Increasing Cache Performance

Adjust `--write-back` and `--read-ahead` values for workload. Higher values use more memory but reduce RPC calls.

### Adding TLS

Generate key/cert and pass via `--key` and `--cert` flags on both client and server.

## File Reference

| File | Lines | Description |
|------|-------|-------------|
| `source/fs.cpp` | 1504 | FUSE low-level operations |
| `source/rpc.cpp` | 1693 | Cap'n Proto RPC server |
| `source/auth.cpp` | 131 | Authentication and access control |
| `standalone/source/main.cpp` | ~400 | CLI application |
| `capnp/ghostfs.capnp` | - | Main protocol interface |
