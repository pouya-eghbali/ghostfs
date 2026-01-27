#!/bin/bash
set -e

# GhostFS Docker Benchmark Entrypoint
# Sets up server/client and runs the built-in benchmark

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
ROOT="/tmp/ghostfs-bench-root"
MOUNT="/tmp/ghostfs-bench-mount"
HOST="127.0.0.1"
PORT="3444"
AUTH_PORT="3445"
USER="benchuser"
CACHE_SIZE="${GHOSTFS_CACHE:-255}"
GHOSTFS="./build/standalone/GhostFS"

# Benchmark settings (can be overridden via env vars)
SMALL_FILES="${GHOSTFS_SMALL_FILES:-1000}"
SMALL_SIZE="${GHOSTFS_SMALL_SIZE:-4096}"
LARGE_SIZE="${GHOSTFS_LARGE_SIZE:-1000}"
JOBS="${GHOSTFS_JOBS:-8}"

cleanup() {
    log_info "Cleaning up..."
    fusermount -u "$MOUNT" 2>/dev/null || true
    pkill -f "GhostFS.*--server" 2>/dev/null || true
    pkill -f "GhostFS.*--client" 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Setup directories
mkdir -p "$ROOT/$USER" "$MOUNT"

# Start server
log_info "Starting GhostFS server..."
$GHOSTFS --server --root "$ROOT" --bind "$HOST" --port "$PORT" --auth-port "$AUTH_PORT" &
sleep 2

# Get token
log_info "Getting authentication token..."
TOKEN=$($GHOSTFS --authorize --host "$HOST" --auth-port "$AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)
if [ -z "$TOKEN" ]; then
    log_error "Failed to get token"
    exit 1
fi

# Mount client
log_info "Mounting GhostFS client (cache=$CACHE_SIZE)..."
$GHOSTFS --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
    --write-back "$CACHE_SIZE" --read-ahead "$CACHE_SIZE" \
    -o big_writes -o max_read=1048576 -o max_write=1048576 "$MOUNT" &
sleep 3

# Verify mount
if ! ls "$MOUNT" &>/dev/null; then
    log_error "Mount failed"
    exit 1
fi

log_info "GhostFS mounted successfully"
echo ""

# Run benchmark
$GHOSTFS --benchmark --dir "$MOUNT" \
    --small-files "$SMALL_FILES" \
    --small-size "$SMALL_SIZE" \
    --large-size "$LARGE_SIZE" \
    --jobs "$JOBS"
