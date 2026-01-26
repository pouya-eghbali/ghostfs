#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ROOT="${GHOSTFS_ROOT:-/data/root}"
MOUNT="${GHOSTFS_MOUNT:-/mnt/ghostfs}"
HOST="${GHOSTFS_HOST:-127.0.0.1}"
PORT="${GHOSTFS_PORT:-3444}"
AUTH_PORT="${GHOSTFS_AUTH_PORT:-3445}"
USER="benchuser"
TOKEN=""

# Benchmark configuration
SMALL_FILE_COUNT=1000
SMALL_FILE_SIZE=4096  # 4KB each
BIG_FILE_SIZE_MB=100  # 100MB

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_result() {
    echo -e "${GREEN}[RESULT]${NC} $1"
}

log_benchmark() {
    echo -e "${BLUE}[BENCH]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."

    # Unmount if mounted
    if mountpoint -q "$MOUNT" 2>/dev/null; then
        fusermount -u "$MOUNT" 2>/dev/null || umount "$MOUNT" 2>/dev/null || true
    fi

    # Kill background processes
    pkill -f "ghostfs.*--server" 2>/dev/null || true
    pkill -f "ghostfs.*--client" 2>/dev/null || true

    # Clean up temp files
    rm -rf /tmp/bench_* 2>/dev/null || true

    sleep 1
}

trap cleanup EXIT

# Format bytes to human readable
format_size() {
    local bytes=$1
    if [ $bytes -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [ $bytes -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [ $bytes -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
    else
        echo "$bytes B"
    fi
}

# Calculate throughput
calc_throughput() {
    local bytes=$1
    local ms=$2
    if [ $ms -gt 0 ]; then
        local bytes_per_sec=$(echo "scale=2; $bytes * 1000 / $ms" | bc)
        format_size $bytes_per_sec
    else
        echo "N/A"
    fi
}

# Setup
log_info "Setting up benchmark environment..."
mkdir -p "$ROOT/$USER"
mkdir -p "$MOUNT"

# Start the server in background
log_info "Starting GhostFS server..."
ghostfs --server --root "$ROOT" --bind "$HOST" --port "$PORT" --auth-port "$AUTH_PORT" &
SERVER_PID=$!
sleep 2

# Check server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Server failed to start"
    exit 1
fi
log_info "Server started (PID: $SERVER_PID)"

# Add a token for the benchmark user
log_info "Adding authentication token..."
TOKEN=$(ghostfs --authorize --host "$HOST" --auth-port "$AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)

if [ -z "$TOKEN" ]; then
    echo "Failed to get authentication token"
    exit 1
fi
log_info "Got token: $TOKEN"

# Mount the filesystem
log_info "Mounting GhostFS client..."
ghostfs --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
    --write-back 64 --read-ahead 64 "$MOUNT" &
CLIENT_PID=$!
sleep 2

# Check if mounted
if ! mountpoint -q "$MOUNT"; then
    echo "Failed to mount filesystem"
    exit 1
fi
log_info "Filesystem mounted at $MOUNT"

# ============================================================================
# Benchmarks
# ============================================================================

echo ""
echo "============================================"
echo "GhostFS Benchmark Suite"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Small files: $SMALL_FILE_COUNT files x $(format_size $SMALL_FILE_SIZE)"
echo "  Big file: $(format_size $((BIG_FILE_SIZE_MB * 1048576)))"
echo ""

# Prepare local test data
log_info "Preparing test data..."
LOCAL_SMALL_DIR="/tmp/bench_small_local"
LOCAL_BIG_FILE="/tmp/bench_big_local.bin"
GHOSTFS_SMALL_DIR="$MOUNT/bench_small"
GHOSTFS_BIG_FILE="$MOUNT/bench_big.bin"
COPYOUT_SMALL_DIR="/tmp/bench_small_copyout"
COPYOUT_BIG_FILE="/tmp/bench_big_copyout.bin"

mkdir -p "$LOCAL_SMALL_DIR"
mkdir -p "$COPYOUT_SMALL_DIR"

# Generate small files
log_info "Generating $SMALL_FILE_COUNT small files..."
for i in $(seq 1 $SMALL_FILE_COUNT); do
    dd if=/dev/urandom of="$LOCAL_SMALL_DIR/file_$i.dat" bs=$SMALL_FILE_SIZE count=1 2>/dev/null
done

# Generate big file
log_info "Generating ${BIG_FILE_SIZE_MB}MB big file..."
dd if=/dev/urandom of="$LOCAL_BIG_FILE" bs=1M count=$BIG_FILE_SIZE_MB 2>/dev/null

TOTAL_SMALL_BYTES=$((SMALL_FILE_COUNT * SMALL_FILE_SIZE))
TOTAL_BIG_BYTES=$((BIG_FILE_SIZE_MB * 1048576))

echo ""
log_benchmark "Starting benchmarks..."
echo ""

# JSON output for CI parsing
JSON_OUTPUT="/tmp/benchmark_results.json"
echo "{" > "$JSON_OUTPUT"
echo '  "benchmarks": [' >> "$JSON_OUTPUT"

# ============================================================================
# Benchmark 1: Small files copy IN (local -> GhostFS)
# ============================================================================
log_benchmark "Benchmark 1: Copy $SMALL_FILE_COUNT small files IN (local -> GhostFS)"

mkdir -p "$GHOSTFS_SMALL_DIR"
sync

START_MS=$(date +%s%3N)
cp -r "$LOCAL_SMALL_DIR"/* "$GHOSTFS_SMALL_DIR/"
sync
sleep 1  # Allow async writes to fully flush
END_MS=$(date +%s%3N)

DURATION_MS=$((END_MS - START_MS))
THROUGHPUT=$(calc_throughput $TOTAL_SMALL_BYTES $DURATION_MS)

log_result "Small files copy IN: ${DURATION_MS}ms (${THROUGHPUT}/s)"
echo "    {\"name\": \"small_files_copy_in\", \"files\": $SMALL_FILE_COUNT, \"bytes\": $TOTAL_SMALL_BYTES, \"duration_ms\": $DURATION_MS}," >> "$JSON_OUTPUT"

# Verify file count on GhostFS
GHOSTFS_COUNT=$(ls "$GHOSTFS_SMALL_DIR" | wc -l)
log_info "Files on GhostFS: $GHOSTFS_COUNT (expected: $SMALL_FILE_COUNT)"

# ============================================================================
# Benchmark 2: Small files copy OUT (GhostFS -> local)
# ============================================================================
log_benchmark "Benchmark 2: Copy $SMALL_FILE_COUNT small files OUT (GhostFS -> local)"

sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true  # Drop page cache if possible

START_MS=$(date +%s%3N)
cp -r "$GHOSTFS_SMALL_DIR"/* "$COPYOUT_SMALL_DIR/"
sync
END_MS=$(date +%s%3N)

DURATION_MS=$((END_MS - START_MS))
THROUGHPUT=$(calc_throughput $TOTAL_SMALL_BYTES $DURATION_MS)

log_result "Small files copy OUT: ${DURATION_MS}ms (${THROUGHPUT}/s)"
echo "    {\"name\": \"small_files_copy_out\", \"files\": $SMALL_FILE_COUNT, \"bytes\": $TOTAL_SMALL_BYTES, \"duration_ms\": $DURATION_MS}," >> "$JSON_OUTPUT"

# Verify file count on copyout
COPYOUT_COUNT=$(ls "$COPYOUT_SMALL_DIR" | wc -l)
log_info "Files copied out: $COPYOUT_COUNT (expected: $SMALL_FILE_COUNT)"

# Verify integrity of small files
log_info "Verifying small files integrity..."
SMALL_HASH_LOCAL=$(find "$LOCAL_SMALL_DIR" -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
SMALL_HASH_COPYOUT=$(find "$COPYOUT_SMALL_DIR" -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)

if [ "$SMALL_HASH_LOCAL" = "$SMALL_HASH_COPYOUT" ]; then
    log_result "Small files integrity: PASSED"
else
    echo -e "${RED}[ERROR]${NC} Small files integrity: FAILED"
    echo "  Local hash:   $SMALL_HASH_LOCAL"
    echo "  Copyout hash: $SMALL_HASH_COPYOUT"
    # Show first few differing files for debugging
    log_info "Finding differing files..."
    DIFF_COUNT=0
    for f in $(ls "$LOCAL_SMALL_DIR"); do
        LOCAL_H=$(sha256sum "$LOCAL_SMALL_DIR/$f" 2>/dev/null | cut -d' ' -f1)
        COPY_H=$(sha256sum "$COPYOUT_SMALL_DIR/$f" 2>/dev/null | cut -d' ' -f1)
        if [ "$LOCAL_H" != "$COPY_H" ]; then
            echo "  DIFF: $f (local: ${LOCAL_H:0:16}... copy: ${COPY_H:0:16}...)"
            DIFF_COUNT=$((DIFF_COUNT + 1))
            if [ $DIFF_COUNT -ge 5 ]; then
                echo "  ... (showing first 5 differences)"
                break
            fi
        fi
    done
fi

# ============================================================================
# Benchmark 3: Big file copy IN (local -> GhostFS)
# ============================================================================
log_benchmark "Benchmark 3: Copy ${BIG_FILE_SIZE_MB}MB big file IN (local -> GhostFS)"

sync

START_MS=$(date +%s%3N)
cp "$LOCAL_BIG_FILE" "$GHOSTFS_BIG_FILE"
sync
END_MS=$(date +%s%3N)

DURATION_MS=$((END_MS - START_MS))
THROUGHPUT=$(calc_throughput $TOTAL_BIG_BYTES $DURATION_MS)

log_result "Big file copy IN: ${DURATION_MS}ms (${THROUGHPUT}/s)"
echo "    {\"name\": \"big_file_copy_in\", \"bytes\": $TOTAL_BIG_BYTES, \"duration_ms\": $DURATION_MS}," >> "$JSON_OUTPUT"

# ============================================================================
# Benchmark 4: Big file copy OUT (GhostFS -> local)
# ============================================================================
log_benchmark "Benchmark 4: Copy ${BIG_FILE_SIZE_MB}MB big file OUT (GhostFS -> local)"

sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true  # Drop page cache if possible

START_MS=$(date +%s%3N)
cp "$GHOSTFS_BIG_FILE" "$COPYOUT_BIG_FILE"
sync
END_MS=$(date +%s%3N)

DURATION_MS=$((END_MS - START_MS))
THROUGHPUT=$(calc_throughput $TOTAL_BIG_BYTES $DURATION_MS)

log_result "Big file copy OUT: ${DURATION_MS}ms (${THROUGHPUT}/s)"
echo "    {\"name\": \"big_file_copy_out\", \"bytes\": $TOTAL_BIG_BYTES, \"duration_ms\": $DURATION_MS}" >> "$JSON_OUTPUT"

# Verify integrity of big file
log_info "Verifying big file integrity..."
BIG_HASH_LOCAL=$(sha256sum "$LOCAL_BIG_FILE" | cut -d' ' -f1)
BIG_HASH_GHOSTFS=$(sha256sum "$GHOSTFS_BIG_FILE" | cut -d' ' -f1)
BIG_HASH_COPYOUT=$(sha256sum "$COPYOUT_BIG_FILE" | cut -d' ' -f1)

if [ "$BIG_HASH_LOCAL" = "$BIG_HASH_GHOSTFS" ] && [ "$BIG_HASH_GHOSTFS" = "$BIG_HASH_COPYOUT" ]; then
    log_result "Big file integrity: PASSED"
else
    echo -e "${RED}[ERROR]${NC} Big file integrity: FAILED"
    echo "  Local hash:   $BIG_HASH_LOCAL"
    echo "  GhostFS hash: $BIG_HASH_GHOSTFS"
    echo "  Copyout hash: $BIG_HASH_COPYOUT"
fi

# Close JSON
echo '  ]' >> "$JSON_OUTPUT"
echo '}' >> "$JSON_OUTPUT"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "============================================"
echo "Benchmark Summary"
echo "============================================"
cat "$JSON_OUTPUT"
echo ""
echo "============================================"

exit 0
