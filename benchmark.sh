#!/bin/bash
set -e

# GhostFS Benchmark Suite
# Run on real hardware for accurate performance measurements

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ROOT="${GHOSTFS_ROOT:-/tmp/ghostfs-bench-root}"
MOUNT="${GHOSTFS_MOUNT:-/tmp/ghostfs-bench-mount}"
HOST="127.0.0.1"
PORT="3444"
AUTH_PORT="3445"
USER="benchuser"
SMALL_FILE_COUNT=1000
SMALL_FILE_SIZE=4096
BIG_FILE_SIZE_MB=1000
CACHE_SIZE="${GHOSTFS_CACHE:-255}"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    IS_MACOS=true
    UNMOUNT_CMD="umount"
else
    IS_MACOS=false
    UNMOUNT_CMD="fusermount -u"
fi

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_result() { echo -e "${GREEN}[RESULT]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    $UNMOUNT_CMD "$MOUNT" 2>/dev/null || true
    pkill -f "GhostFS.*--server" 2>/dev/null || true
    pkill -f "GhostFS.*--client" 2>/dev/null || true
    rm -rf /tmp/ghostfs-bench-* 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

calc_throughput() {
    local bytes=$1 ms=$2
    if [ "$ms" -gt 0 ]; then
        echo "scale=2; $bytes / 1048576 * 1000 / $ms" | bc
    else
        echo "0"
    fi
}

# Find GhostFS binary
if [ -x "./build/standalone/GhostFS" ]; then
    GHOSTFS="./build/standalone/GhostFS"
elif command -v ghostfs &>/dev/null; then
    GHOSTFS="ghostfs"
elif command -v GhostFS &>/dev/null; then
    GHOSTFS="GhostFS"
else
    log_error "GhostFS binary not found. Build it first: cmake -S standalone -B build/standalone && cmake --build build/standalone"
    exit 1
fi

log_info "Using GhostFS: $GHOSTFS"

# Setup
mkdir -p "$ROOT/$USER" "$MOUNT"

# Start server
log_info "Starting server..."
$GHOSTFS --server --root "$ROOT" --bind "$HOST" --port "$PORT" --auth-port "$AUTH_PORT" &
sleep 2

# Get token
TOKEN=$($GHOSTFS --authorize --host "$HOST" --auth-port "$AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)
if [ -z "$TOKEN" ]; then
    log_error "Failed to get token"
    exit 1
fi

# Mount client
log_info "Mounting client (cache=$CACHE_SIZE)..."
if $IS_MACOS; then
    $GHOSTFS --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
        --write-back "$CACHE_SIZE" --read-ahead "$CACHE_SIZE" "$MOUNT" &
else
    $GHOSTFS --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
        --write-back "$CACHE_SIZE" --read-ahead "$CACHE_SIZE" \
        -o big_writes -o max_read=1048576 -o max_write=1048576 "$MOUNT" &
fi
sleep 3

if ! ls "$MOUNT" &>/dev/null; then
    log_error "Mount failed"
    exit 1
fi

# Generate test data
log_info "Generating test data..."
LOCAL_DIR="/tmp/ghostfs-bench-local"
mkdir -p "$LOCAL_DIR/small"

for i in $(seq 1 $SMALL_FILE_COUNT); do
    dd if=/dev/urandom of="$LOCAL_DIR/small/file_$i.dat" bs=$SMALL_FILE_SIZE count=1 2>/dev/null
done

dd if=/dev/urandom of="$LOCAL_DIR/big.bin" bs=1M count=$BIG_FILE_SIZE_MB 2>/dev/null

TOTAL_SMALL=$((SMALL_FILE_COUNT * SMALL_FILE_SIZE))
TOTAL_BIG=$((BIG_FILE_SIZE_MB * 1048576))

echo ""
echo "============================================"
echo "GhostFS Benchmark"
echo "============================================"
echo "Small files: $SMALL_FILE_COUNT x 4KB = $((TOTAL_SMALL / 1024))KB"
echo "Big file: ${BIG_FILE_SIZE_MB}MB"
echo "Cache size: $CACHE_SIZE"
echo "============================================"
echo ""

mkdir -p "$MOUNT/bench"
COPYOUT="/tmp/ghostfs-bench-out"
mkdir -p "$COPYOUT"

# Small files IN (parallel)
log_info "Small files copy IN..."
START=$(date +%s%3N)
find "$LOCAL_DIR/small" -type f -print0 | xargs -0 -P 8 -I {} cp {} "$MOUNT/bench/"
sync
END=$(date +%s%3N)
SMALL_IN_MS=$((END - START))
SMALL_IN_THROUGHPUT=$(calc_throughput $TOTAL_SMALL $SMALL_IN_MS)
log_result "Small files IN: ${SMALL_IN_MS}ms (${SMALL_IN_THROUGHPUT} MB/s)"

# Small files OUT (parallel read)
log_info "Small files copy OUT..."
if ! $IS_MACOS; then
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
fi
START=$(date +%s%3N)
find "$MOUNT/bench" -type f -print0 | xargs -0 -P 8 cat > /dev/null
END=$(date +%s%3N)
SMALL_OUT_MS=$((END - START))
SMALL_OUT_THROUGHPUT=$(calc_throughput $TOTAL_SMALL $SMALL_OUT_MS)
log_result "Small files OUT: ${SMALL_OUT_MS}ms (${SMALL_OUT_THROUGHPUT} MB/s)"

# Big file IN
log_info "Big file copy IN..."
START=$(date +%s%3N)
cp "$LOCAL_DIR/big.bin" "$MOUNT/big.bin"
sync
END=$(date +%s%3N)
BIG_IN_MS=$((END - START))
BIG_IN_THROUGHPUT=$(calc_throughput $TOTAL_BIG $BIG_IN_MS)
log_result "Big file IN: ${BIG_IN_MS}ms (${BIG_IN_THROUGHPUT} MB/s)"

# Big file OUT (pure read - no local disk write overhead)
log_info "Big file copy OUT..."
if ! $IS_MACOS; then
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
fi
START=$(date +%s%3N)
cat "$MOUNT/big.bin" > /dev/null
END=$(date +%s%3N)
BIG_OUT_MS=$((END - START))
BIG_OUT_THROUGHPUT=$(calc_throughput $TOTAL_BIG $BIG_OUT_MS)
log_result "Big file OUT: ${BIG_OUT_MS}ms (${BIG_OUT_THROUGHPUT} MB/s)"

# Copy for verification (not timed)
cp "$MOUNT/big.bin" "$COPYOUT/big.bin"

# Verify
log_info "Verifying integrity..."
if $IS_MACOS; then
    HASH_CMD="shasum -a 256"
else
    HASH_CMD="sha256sum"
fi

ORIG_HASH=$($HASH_CMD "$LOCAL_DIR/big.bin" | cut -d' ' -f1)
COPY_HASH=$($HASH_CMD "$COPYOUT/big.bin" | cut -d' ' -f1)

if [ "$ORIG_HASH" = "$COPY_HASH" ]; then
    log_result "Integrity: PASSED"
else
    log_error "Integrity: FAILED"
fi

echo ""
echo "============================================"
echo "Summary"
echo "============================================"
echo "Small files (${SMALL_FILE_COUNT} x 4KB):"
echo "  Write: ${SMALL_IN_THROUGHPUT} MB/s"
echo "  Read:  ${SMALL_OUT_THROUGHPUT} MB/s"
echo ""
echo "Big file (${BIG_FILE_SIZE_MB}MB):"
echo "  Write: ${BIG_IN_THROUGHPUT} MB/s"
echo "  Read:  ${BIG_OUT_THROUGHPUT} MB/s"
echo "============================================"
