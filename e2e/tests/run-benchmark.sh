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
BIG_FILE_SIZE_MB=1000  # 1000MB (1GB)
CACHE_SIZES=(8 32 64 128 255)  # Different cache sizes to test

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
    local int_bytes=$(echo "$bytes" | cut -d'.' -f1)
    if [ "$int_bytes" -ge 1073741824 ] 2>/dev/null; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [ "$int_bytes" -ge 1048576 ] 2>/dev/null; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [ "$int_bytes" -ge 1024 ] 2>/dev/null; then
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

# Tune network parameters for better throughput
tune_network() {
    log_info "Tuning network parameters..."
    # Increase TCP buffer sizes
    sysctl -w net.core.rmem_max=16777216 2>/dev/null || true
    sysctl -w net.core.wmem_max=16777216 2>/dev/null || true
    sysctl -w net.ipv4.tcp_rmem="4096 1048576 16777216" 2>/dev/null || true
    sysctl -w net.ipv4.tcp_wmem="4096 1048576 16777216" 2>/dev/null || true
    # Disable Nagle's algorithm effect
    sysctl -w net.ipv4.tcp_low_latency=1 2>/dev/null || true
}

# Mount filesystem with specific cache size
mount_with_cache() {
    local cache_size=$1

    # Unmount if already mounted
    if mountpoint -q "$MOUNT" 2>/dev/null; then
        fusermount -u "$MOUNT" 2>/dev/null || umount "$MOUNT" 2>/dev/null || true
        sleep 1
    fi

    # FUSE options for better performance:
    # - big_writes: enable large write requests
    # - max_read/max_write: increase max I/O size to 1MB
    # - async_read: async read operations
    ghostfs --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
        --write-back "$cache_size" --read-ahead "$cache_size" \
        -o big_writes -o max_read=1048576 -o max_write=1048576 -o async_read \
        "$MOUNT" &
    sleep 2

    if ! mountpoint -q "$MOUNT"; then
        echo "Failed to mount filesystem with cache size $cache_size"
        return 1
    fi
    return 0
}

# Setup
log_info "Setting up benchmark environment..."
mkdir -p "$ROOT/$USER"
mkdir -p "$MOUNT"

# Apply network tuning
tune_network

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

# ============================================================================
# Prepare test data
# ============================================================================

echo ""
echo "============================================"
echo "GhostFS Benchmark Suite"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Small files: $SMALL_FILE_COUNT files x $(format_size $SMALL_FILE_SIZE)"
echo "  Big file: $(format_size $((BIG_FILE_SIZE_MB * 1048576)))"
echo "  Cache sizes to test: ${CACHE_SIZES[*]}"
echo ""

LOCAL_SMALL_DIR="/tmp/bench_small_local"
LOCAL_BIG_FILE="/tmp/bench_big_local.bin"

mkdir -p "$LOCAL_SMALL_DIR"

# Generate small files
log_info "Generating $SMALL_FILE_COUNT small files..."
for i in $(seq 1 $SMALL_FILE_COUNT); do
    dd if=/dev/urandom of="$LOCAL_SMALL_DIR/file_$i.dat" bs=$SMALL_FILE_SIZE count=1 2>/dev/null
done

# Generate big file
log_info "Generating ${BIG_FILE_SIZE_MB}MB big file (this may take a moment)..."
dd if=/dev/urandom of="$LOCAL_BIG_FILE" bs=1M count=$BIG_FILE_SIZE_MB 2>/dev/null

# Calculate hashes for verification
log_info "Calculating source file hashes..."
SMALL_HASH_EXPECTED=$(cd "$LOCAL_SMALL_DIR" && find . -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
BIG_HASH_EXPECTED=$(sha256sum "$LOCAL_BIG_FILE" | cut -d' ' -f1)

TOTAL_SMALL_BYTES=$((SMALL_FILE_COUNT * SMALL_FILE_SIZE))
TOTAL_BIG_BYTES=$((BIG_FILE_SIZE_MB * 1048576))

# JSON output for CI parsing
JSON_OUTPUT="/tmp/benchmark_results.json"
echo "{" > "$JSON_OUTPUT"
echo '  "config": {' >> "$JSON_OUTPUT"
echo "    \"small_file_count\": $SMALL_FILE_COUNT," >> "$JSON_OUTPUT"
echo "    \"small_file_size\": $SMALL_FILE_SIZE," >> "$JSON_OUTPUT"
echo "    \"big_file_size_mb\": $BIG_FILE_SIZE_MB" >> "$JSON_OUTPUT"
echo '  },' >> "$JSON_OUTPUT"
echo '  "benchmarks": [' >> "$JSON_OUTPUT"

FIRST_ENTRY=true

# ============================================================================
# Run benchmarks for each cache size
# ============================================================================

for CACHE_SIZE in "${CACHE_SIZES[@]}"; do
    echo ""
    echo "============================================"
    log_benchmark "Testing with cache size: $CACHE_SIZE"
    echo "============================================"

    # Mount with this cache size
    if ! mount_with_cache "$CACHE_SIZE"; then
        continue
    fi

    # Prepare GhostFS directories
    GHOSTFS_SMALL_DIR="$MOUNT/bench_small_$CACHE_SIZE"
    GHOSTFS_BIG_FILE="$MOUNT/bench_big_$CACHE_SIZE.bin"
    COPYOUT_SMALL_DIR="/tmp/bench_small_copyout_$CACHE_SIZE"
    COPYOUT_BIG_FILE="/tmp/bench_big_copyout_$CACHE_SIZE.bin"

    mkdir -p "$GHOSTFS_SMALL_DIR"
    mkdir -p "$COPYOUT_SMALL_DIR"

    # Add comma separator for JSON
    if [ "$FIRST_ENTRY" = false ]; then
        echo "," >> "$JSON_OUTPUT"
    fi
    FIRST_ENTRY=false

    # ------------------------------------------------------------------------
    # Benchmark: Small files copy IN
    # ------------------------------------------------------------------------
    log_benchmark "Small files copy IN (cache=$CACHE_SIZE)..."
    sync

    START_MS=$(date +%s%3N)
    cp -r "$LOCAL_SMALL_DIR"/* "$GHOSTFS_SMALL_DIR/"
    sync
    sleep 1
    END_MS=$(date +%s%3N)

    SMALL_IN_MS=$((END_MS - START_MS))
    SMALL_IN_THROUGHPUT=$(calc_throughput $TOTAL_SMALL_BYTES $SMALL_IN_MS)
    log_result "Small files copy IN: ${SMALL_IN_MS}ms (${SMALL_IN_THROUGHPUT}/s)"

    # ------------------------------------------------------------------------
    # Benchmark: Small files copy OUT
    # ------------------------------------------------------------------------
    log_benchmark "Small files copy OUT (cache=$CACHE_SIZE)..."
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

    START_MS=$(date +%s%3N)
    cp -r "$GHOSTFS_SMALL_DIR"/* "$COPYOUT_SMALL_DIR/"
    sync
    END_MS=$(date +%s%3N)

    SMALL_OUT_MS=$((END_MS - START_MS))
    SMALL_OUT_THROUGHPUT=$(calc_throughput $TOTAL_SMALL_BYTES $SMALL_OUT_MS)
    log_result "Small files copy OUT: ${SMALL_OUT_MS}ms (${SMALL_OUT_THROUGHPUT}/s)"

    # Verify small files integrity
    SMALL_HASH_ACTUAL=$(cd "$COPYOUT_SMALL_DIR" && find . -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
    if [ "$SMALL_HASH_EXPECTED" = "$SMALL_HASH_ACTUAL" ]; then
        log_result "Small files integrity: PASSED"
        SMALL_INTEGRITY="true"
    else
        echo -e "${RED}[ERROR]${NC} Small files integrity: FAILED"
        SMALL_INTEGRITY="false"
    fi

    # ------------------------------------------------------------------------
    # Benchmark: Big file copy IN
    # ------------------------------------------------------------------------
    log_benchmark "Big file copy IN (cache=$CACHE_SIZE)..."
    sync

    START_MS=$(date +%s%3N)
    cp "$LOCAL_BIG_FILE" "$GHOSTFS_BIG_FILE"
    sync
    END_MS=$(date +%s%3N)

    BIG_IN_MS=$((END_MS - START_MS))
    BIG_IN_THROUGHPUT=$(calc_throughput $TOTAL_BIG_BYTES $BIG_IN_MS)
    log_result "Big file copy IN: ${BIG_IN_MS}ms (${BIG_IN_THROUGHPUT}/s)"

    # ------------------------------------------------------------------------
    # Benchmark: Big file copy OUT
    # ------------------------------------------------------------------------
    log_benchmark "Big file copy OUT (cache=$CACHE_SIZE)..."
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

    START_MS=$(date +%s%3N)
    cp "$GHOSTFS_BIG_FILE" "$COPYOUT_BIG_FILE"
    sync
    END_MS=$(date +%s%3N)

    BIG_OUT_MS=$((END_MS - START_MS))
    BIG_OUT_THROUGHPUT=$(calc_throughput $TOTAL_BIG_BYTES $BIG_OUT_MS)
    log_result "Big file copy OUT: ${BIG_OUT_MS}ms (${BIG_OUT_THROUGHPUT}/s)"

    # Verify big file integrity
    BIG_HASH_ACTUAL=$(sha256sum "$COPYOUT_BIG_FILE" | cut -d' ' -f1)
    if [ "$BIG_HASH_EXPECTED" = "$BIG_HASH_ACTUAL" ]; then
        log_result "Big file integrity: PASSED"
        BIG_INTEGRITY="true"
    else
        echo -e "${RED}[ERROR]${NC} Big file integrity: FAILED"
        BIG_INTEGRITY="false"
    fi

    # Write JSON entry
    cat >> "$JSON_OUTPUT" << EOF
    {
      "cache_size": $CACHE_SIZE,
      "small_files": {
        "copy_in_ms": $SMALL_IN_MS,
        "copy_out_ms": $SMALL_OUT_MS,
        "integrity": $SMALL_INTEGRITY
      },
      "big_file": {
        "copy_in_ms": $BIG_IN_MS,
        "copy_out_ms": $BIG_OUT_MS,
        "integrity": $BIG_INTEGRITY
      }
    }
EOF

    # Clean up for next iteration
    rm -rf "$COPYOUT_SMALL_DIR" "$COPYOUT_BIG_FILE"
done

# Close JSON
echo "" >> "$JSON_OUTPUT"
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
