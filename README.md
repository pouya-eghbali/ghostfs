<h1 align="center">GhostFS</h1>

<p align="center">
  <strong>A distributed filesystem that serves any storage backend over the network</strong>
</p>

<p align="center">
  <a href="https://github.com/pouya-eghbali/ghostfs/actions/workflows/ubuntu-build.yml">
    <img src="https://github.com/pouya-eghbali/ghostfs/actions/workflows/ubuntu-build.yml/badge.svg" alt="Build Status">
  </a>
  <a href="https://github.com/pouya-eghbali/ghostfs/actions/workflows/e2e-test.yml">
    <img src="https://github.com/pouya-eghbali/ghostfs/actions/workflows/e2e-test.yml/badge.svg" alt="E2E Tests">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-BSL--1.1-blue.svg" alt="License">
  </a>
</p>

---

GhostFS is a FUSE-based distributed filesystem that exposes any local filesystem over the network using high-performance Cap'n Proto RPC. Mount remote storage locally and access files as if they were on your machine.

## Features

- **Network Filesystem** - Mount remote directories locally via FUSE
- **High Performance** - Cap'n Proto RPC with write-back and read-ahead caching
- **Secure** - Token-based authentication with TLS encryption support
- **Flexible Access Control** - Per-user directories and soft mounts for fine-grained permissions
- **Backend Agnostic** - Works with any filesystem (ext4, ZFS, Ceph, NFS, etc.)
- **Lightweight** - Single binary, minimal dependencies at runtime

## Quick Start

### Installation

Download the latest binary from [Releases](https://github.com/pouya-eghbali/ghostfs/releases) or build from source.

### Start the Server

```bash
# Create a directory to serve
mkdir -p ~/.ghostfs/root

# Start GhostFS server
ghostfs --server --root ~/.ghostfs/root --bind 0.0.0.0 --port 3444
```

### Create a User Token

```bash
# In another terminal, create a token for a user
ghostfs --authorize --host 127.0.0.1 --auth-port 3445 --user myuser --retries -1
# Output: <token>
```

### Mount the Filesystem

```bash
# Create mount point
mkdir -p /mnt/ghostfs

# Mount (replace <token> with the token from above)
ghostfs --client --host 127.0.0.1 --port 3444 --user myuser --token <token> /mnt/ghostfs

# Now use /mnt/ghostfs like any other directory!
ls /mnt/ghostfs
echo "Hello GhostFS" > /mnt/ghostfs/test.txt
```

## Usage

```
GhostFS - Distributed Filesystem

USAGE:
  ghostfs [options] [mountpoint]

MODES:
  --server, -s          Run as filesystem server
  --client, -c          Run as FUSE client (requires mountpoint)
  --authorize, -A       Run authorization commands

SERVER OPTIONS:
  --root, -r <path>     Root directory to serve (default: ~/.ghostfs/root)
  --bind, -b <addr>     Bind address (default: 127.0.0.1)
  --port, -p <port>     Server port (default: 3444)
  --auth-port, -P       Auth server port (default: 3445)
  --suffix, -S <path>   User subdirectory suffix

CLIENT OPTIONS:
  --host, -H <addr>     Server address (default: 127.0.0.1)
  --port, -p <port>     Server port (default: 3444)
  --user, -u <name>     Username
  --token, -t <token>   Authentication token
  --write-back, -w <n>  Write cache entries (default: 8)
  --read-ahead, -C <n>  Read cache entries (default: 8)
  --options, -o <opts>  FUSE mount options

TLS OPTIONS:
  --key, -k <file>      TLS private key file
  --cert, -T <file>     TLS certificate file

AUTHORIZATION:
  --user, -u <name>     Username to authorize
  --token, -t <token>   Specific token (optional, auto-generated if omitted)
  --retries, -R <n>     Token usage limit (-1 for unlimited)
  --mount, -m           Create soft mount
  --unmount, -U         Remove soft mount
  --mounts, -M          List user's soft mounts
  --source, -F <path>   Soft mount source directory
  --destination, -d     Soft mount destination
```

## Architecture

```
┌─────────────────┐                          ┌─────────────────┐
│   FUSE Client   │   Cap'n Proto RPC        │   RPC Server    │
│                 │ ◄──────────────────────► │                 │
│  Local Mount    │      (TLS optional)      │  Backend FS     │
└─────────────────┘                          └─────────────────┘
        │                                            │
        ▼                                            ▼
   /mnt/ghostfs                               ~/.ghostfs/root
```

GhostFS consists of two components:

1. **Server**: Exposes a local directory over the network via Cap'n Proto RPC
2. **Client**: Mounts the remote filesystem locally using FUSE

## Building from Source

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake g++ libfuse-dev libssl-dev zlib1g-dev

# Fedora/RHEL
sudo dnf install cmake gcc-c++ fuse-devel openssl-devel zlib-devel

# Arch Linux
sudo pacman -S cmake base-devel fuse2 openssl zlib
```

### Build

```bash
git clone https://github.com/pouya-eghbali/ghostfs.git
cd ghostfs

# Build
cmake -S standalone -B build/standalone
cmake --build build/standalone -j$(nproc)

# Binary is at build/standalone/GhostFS
./build/standalone/GhostFS --help
```

## Testing

### Unit Tests

```bash
cmake -S test -B build/test
cmake --build build/test
ctest --test-dir build/test
```

### E2E Tests (Docker)

```bash
cd e2e
docker compose up --build --exit-code-from ghostfs
```

## Configuration Examples

### Production Server with TLS

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start server with TLS
ghostfs --server \
  --root /data/storage \
  --bind 0.0.0.0 \
  --port 3444 \
  --key key.pem \
  --cert cert.pem
```

### Client with TLS

```bash
ghostfs --client \
  --host storage.example.com \
  --port 3444 \
  --user myuser \
  --token <token> \
  --cert cert.pem \
  /mnt/remote
```

### Soft Mounts (Extended Access)

Soft mounts allow users to access directories outside their home folder:

```bash
# Grant user access to /shared/data mounted at /data in their view
ghostfs --authorize \
  --host 127.0.0.1 \
  --user myuser \
  --mount \
  --source /shared/data \
  --destination /data
```

### Performance Tuning

```bash
# Increase cache sizes for better performance on high-latency connections
ghostfs --client \
  --write-back 32 \
  --read-ahead 32 \
  ...
```

## Benchmarking

GhostFS includes a benchmark suite to measure throughput on your hardware.

### Native Benchmark

```bash
# Build first
cmake -S standalone -B build/standalone
cmake --build build/standalone -j$(nproc)

# Run benchmark
./benchmark.sh

# With custom cache size
GHOSTFS_CACHE=128 ./benchmark.sh
```

### Docker Benchmark (Linux)

```bash
docker build -f Dockerfile.benchmark -t ghostfs-bench .
docker run --rm --privileged --device /dev/fuse --cap-add SYS_ADMIN ghostfs-bench
```

### Expected Performance

On Linux (Docker on M1 MacBook Pro, localhost):

| Test | Throughput |
|------|------------|
| Large file write (1GB) | ~610 MB/s |
| Large file read (1GB) | ~640 MB/s |
| Small files write (1000 x 4KB) | ~1140 files/s |
| Small files read (1000 x 4KB) | ~1435 files/s |

Performance varies based on hardware, network latency, and cache settings. macOS performance is roughly 2x slower due to macFUSE overhead.

## License

GhostFS is licensed under the [Business Source License 1.1](LICENSE).

- **Free** for self-hosted, non-commercial use (including personal and research purposes)
- **Commercial/hosted use** requires a license - visit [ghostfs.io](https://ghostfs.io) for details
- Converts to AGPL v3.0 ten years after each version's release

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Links

- **Website**: [ghostfs.io](https://ghostfs.io)
- **Issues**: [GitHub Issues](https://github.com/pouya-eghbali/ghostfs/issues)
- **Releases**: [GitHub Releases](https://github.com/pouya-eghbali/ghostfs/releases)
