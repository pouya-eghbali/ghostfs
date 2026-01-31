#!/bin/bash
set -e

# GhostFS vs Others Benchmark
# Compares GhostFS, SSHFS, and JuiceFS using the built-in GhostFS benchmark
#
# Environment variables for customization:
#   BENCH_SMALL_FILES - Number of small files (default: 1000)
#   BENCH_SMALL_SIZE  - Size of small files in bytes (default: 4096)
#   BENCH_LARGE_SIZE  - Size of large file in MB (default: 1000)
#   BENCH_JOBS        - Parallel jobs for benchmark (default: 8)
#
# Example: docker run --rm --privileged --device /dev/fuse \
#   -e BENCH_SMALL_FILES=2000 -e BENCH_LARGE_SIZE=2000 \
#   ghostfs-vs-benchmark

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Configuration
GHOSTFS_BIN="./build/standalone/GhostFS"
GHOSTFS_ROOT="/benchmark/ghostfs-root"
GHOSTFS_MOUNT="/benchmark/ghostfs-mount"
SSHFS_ROOT="/benchmark/sshfs-root"
SSHFS_MOUNT="/benchmark/sshfs-mount"
JUICEFS_DATA="/benchmark/juicefs-data"
JUICEFS_MOUNT="/benchmark/juicefs-mount"

HOST="127.0.0.1"
GHOSTFS_PORT="3444"
GHOSTFS_AUTH_PORT="3445"
USER="benchuser"

# Benchmark settings
SMALL_FILES="${BENCH_SMALL_FILES:-1000}"
SMALL_SIZE="${BENCH_SMALL_SIZE:-4096}"
LARGE_SIZE="${BENCH_LARGE_SIZE:-1000}"
JOBS="${BENCH_JOBS:-8}"

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${BOLD}${CYAN}$1${NC}"; }

# Get memory usage (RSS in MB) for a process pattern
get_mem_mb() {
    local pattern="$1"
    local total=0
    # Sum RSS of all matching processes (in KB), convert to MB
    while read -r rss; do
        total=$((total + rss))
    done < <(pgrep -f "$pattern" 2>/dev/null | xargs -I{} cat /proc/{}/status 2>/dev/null | grep "VmRSS:" | awk '{print $2}')
    echo $((total / 1024))
}

# Measure memory for all filesystem components
measure_memory() {
    local label="$1"

    # GhostFS components
    GHOSTFS_SERVER_MEM=$(get_mem_mb "GhostFS.*--server")
    GHOSTFS_CLIENT_MEM=$(get_mem_mb "GhostFS.*--client")
    GHOSTFS_TOTAL_MEM=$((GHOSTFS_SERVER_MEM + GHOSTFS_CLIENT_MEM))

    # JuiceFS components
    JUICEFS_CLIENT_MEM=$(get_mem_mb "juicefs.*mount")
    MINIO_MEM=$(get_mem_mb "minio server")
    REDIS_MEM=$(get_mem_mb "redis-server")
    JUICEFS_TOTAL_MEM=$((JUICEFS_CLIENT_MEM + MINIO_MEM + REDIS_MEM))

    # SSHFS components
    SSHFS_CLIENT_MEM=$(get_mem_mb "sshfs")
    SSHD_MEM=$(get_mem_mb "sshd")
    SSHFS_TOTAL_MEM=$((SSHFS_CLIENT_MEM + SSHD_MEM))

    echo ""
    echo -e "${BOLD}Memory Usage ($label):${NC}"
    echo -e "  GhostFS:  server=${GHOSTFS_SERVER_MEM}MB client=${GHOSTFS_CLIENT_MEM}MB ${BOLD}total=${GHOSTFS_TOTAL_MEM}MB${NC}"
    echo -e "  JuiceFS:  client=${JUICEFS_CLIENT_MEM}MB minio=${MINIO_MEM}MB redis=${REDIS_MEM}MB ${BOLD}total=${JUICEFS_TOTAL_MEM}MB${NC}"
    echo -e "  SSHFS:    client=${SSHFS_CLIENT_MEM}MB sshd=${SSHD_MEM}MB ${BOLD}total=${SSHFS_TOTAL_MEM}MB${NC}"
    echo ""

    # Store for final comparison
    eval "MEM_${label}_GHOSTFS=${GHOSTFS_TOTAL_MEM}"
    eval "MEM_${label}_JUICEFS=${JUICEFS_TOTAL_MEM}"
    eval "MEM_${label}_SSHFS=${SSHFS_TOTAL_MEM}"
}

cleanup() {
    log_info "Cleaning up..."
    fusermount -u "$GHOSTFS_MOUNT" 2>/dev/null || true
    fusermount -u "$SSHFS_MOUNT" 2>/dev/null || true
    fusermount -u "$JUICEFS_MOUNT" 2>/dev/null || true
    pkill -f "GhostFS.*--server" 2>/dev/null || true
    pkill -f "GhostFS.*--client" 2>/dev/null || true
    pkill -f sshd 2>/dev/null || true
    pkill -f redis-server 2>/dev/null || true
    pkill -f minio 2>/dev/null || true
}

trap cleanup EXIT

# Start SSH server for SSHFS
start_ssh() {
    log_info "Starting SSH server..."
    /usr/sbin/sshd
    sleep 1

    # Add localhost to known_hosts to avoid prompt
    ssh-keyscan -H localhost >> /root/.ssh/known_hosts 2>/dev/null
    log_success "SSH server started"
}

# Start Redis for JuiceFS metadata
start_redis() {
    log_info "Starting Redis (JuiceFS metadata)..."
    redis-server --daemonize yes --port 6379
    sleep 1
    log_success "Redis started"
}

# Start MinIO S3 server for JuiceFS storage backend
start_minio() {
    log_info "Starting MinIO (S3 backend for JuiceFS)..."
    mkdir -p /benchmark/minio-data
    export MINIO_ROOT_USER=minioadmin
    export MINIO_ROOT_PASSWORD=minioadmin
    minio server /benchmark/minio-data --address ":9000" --console-address ":9001" &>/dev/null &
    sleep 2
    log_success "MinIO started on :9000"
}

# Start GhostFS server
start_ghostfs_server() {
    log_info "Starting GhostFS server..."
    $GHOSTFS_BIN --server --root "$GHOSTFS_ROOT" --bind "$HOST" --port "$GHOSTFS_PORT" --auth-port "$GHOSTFS_AUTH_PORT" &
    sleep 2
    log_success "GhostFS server started"
}

# Mount GhostFS
mount_ghostfs() {
    log_info "Mounting GhostFS..."

    # Get token
    TOKEN=$($GHOSTFS_BIN --authorize --host "$HOST" --auth-port "$GHOSTFS_AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)
    if [ -z "$TOKEN" ]; then
        log_error "Failed to get GhostFS token"
        return 1
    fi

    $GHOSTFS_BIN --client --host "$HOST" --port "$GHOSTFS_PORT" --user "$USER" --token "$TOKEN" \
        --write-back 255 --read-ahead 32 \
        -o big_writes "$GHOSTFS_MOUNT" &
    sleep 3

    if ls "$GHOSTFS_MOUNT" &>/dev/null; then
        log_success "GhostFS mounted"
        return 0
    else
        log_error "GhostFS mount failed"
        return 1
    fi
}

# Mount SSHFS
mount_sshfs() {
    log_info "Mounting SSHFS..."

    sshfs -o StrictHostKeyChecking=no,IdentityFile=/root/.ssh/id_rsa \
        -o allow_other,reconnect,ServerAliveInterval=15 \
        -o cache=yes,cache_timeout=120 \
        root@localhost:"$SSHFS_ROOT" "$SSHFS_MOUNT"
    sleep 1

    if ls "$SSHFS_MOUNT" &>/dev/null; then
        log_success "SSHFS mounted"
        return 0
    else
        log_error "SSHFS mount failed"
        return 1
    fi
}

# Mount JuiceFS (using MinIO S3 backend)
mount_juicefs() {
    log_info "Setting up JuiceFS (S3 backend via MinIO)..."

    # Format JuiceFS filesystem with MinIO S3 backend
    # This ensures JuiceFS data goes through network (S3) just like GhostFS and SSHFS
    juicefs format \
        --storage s3 \
        --bucket http://127.0.0.1:9000/juicefs \
        --access-key minioadmin \
        --secret-key minioadmin \
        redis://localhost:6379/1 benchmark-jfs 2>/dev/null || true

    # Mount JuiceFS with ALL caching disabled for fair comparison
    # --cache-size 0: disable disk cache
    # --buffer-size 64: minimal buffer (can't be 0)
    # --prefetch 0: disable prefetching
    # --attr-cache 0: disable attribute cache
    # --entry-cache 0: disable entry cache
    # --dir-entry-cache 0: disable directory entry cache
    # --open-cache 0: disable open file cache
    juicefs mount -d redis://localhost:6379/1 "$JUICEFS_MOUNT" \
        --cache-size 0 \
        --buffer-size 64 \
        --prefetch 0 \
        --attr-cache 0 \
        --entry-cache 0 \
        --dir-entry-cache 0 \
        --open-cache 0 \
        --no-usage-report 2>/dev/null
    sleep 2

    if ls "$JUICEFS_MOUNT" &>/dev/null; then
        log_success "JuiceFS mounted (S3 backend, no cache/prefetch)"
        return 0
    else
        log_error "JuiceFS mount failed"
        return 1
    fi
}

# Run benchmark on a directory and capture results
run_benchmark() {
    local name="$1"
    local dir="$2"
    local output_file="/tmp/bench_${name}.txt"

    log_info "Running benchmark on $name..."

    # Run the GhostFS benchmark command
    $GHOSTFS_BIN --benchmark --dir "$dir" \
        --small-files "$SMALL_FILES" \
        --small-size "$SMALL_SIZE" \
        --large-size "$LARGE_SIZE" \
        --jobs "$JOBS" \
        --no-verify 2>&1 | tee "$output_file"

    # Extract results - parse based on the output format:
    # "    Write                     Xms     123.4 files/s"
    # The benchmark outputs results in a table with "Write" and "Read" rows

    # Small files section has "files/s", Large file section has "MB/s"
    # We extract based on which metric appears on the line

    # Small Write: first line with both "Write" and "files/s"
    SMALL_WRITE=$(grep "Write" "$output_file" | grep "files/s" | grep -oE '[0-9]+\.[0-9]+ files/s' | head -1 | grep -oE '[0-9]+\.[0-9]+')
    # Small Read: first line with both "Read" and "files/s"
    SMALL_READ=$(grep "Read" "$output_file" | grep "files/s" | grep -oE '[0-9]+\.[0-9]+ files/s' | head -1 | grep -oE '[0-9]+\.[0-9]+')
    # Large Write: first line with both "Write" and "MB/s"
    LARGE_WRITE=$(grep "Write" "$output_file" | grep "MB/s" | grep -oE '[0-9]+\.[0-9]+ MB/s' | head -1 | grep -oE '[0-9]+\.[0-9]+')
    # Large Read: first line with both "Read" and "MB/s"
    LARGE_READ=$(grep "Read" "$output_file" | grep "MB/s" | grep -oE '[0-9]+\.[0-9]+ MB/s' | head -1 | grep -oE '[0-9]+\.[0-9]+')

    # Store results in global arrays
    eval "${name}_SMALL_WRITE='${SMALL_WRITE:-0}'"
    eval "${name}_SMALL_READ='${SMALL_READ:-0}'"
    eval "${name}_LARGE_WRITE='${LARGE_WRITE:-0}'"
    eval "${name}_LARGE_READ='${LARGE_READ:-0}'"

    # Cleanup benchmark files (use sync and retry for FUSE filesystems)
    sync 2>/dev/null || true
    sleep 1
    rm -rf "$dir/ghostfs-bench" 2>/dev/null || {
        # Fallback: remove files first, then directory
        sync 2>/dev/null || true
        find "$dir/ghostfs-bench" -type f -delete 2>/dev/null || true
        find "$dir/ghostfs-bench" -type d -empty -delete 2>/dev/null || true
        rm -rf "$dir/ghostfs-bench" 2>/dev/null || true
    }

    echo ""
}

# Print comparison table
print_comparison() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Filesystem Comparison Results${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${DIM}  Configuration: ${SMALL_FILES} small files (${SMALL_SIZE} bytes), ${LARGE_SIZE} MB large file${NC}"
    echo ""

    printf "  ${BOLD}%-16s %14s %14s %14s %14s${NC}\n" "Filesystem" "Small Write" "Small Read" "Large Write" "Large Read"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────────${NC}"

    printf "  %-16s %11s f/s %11s f/s %11s MB/s %11s MB/s\n" \
        "GhostFS" "$GHOSTFS_SMALL_WRITE" "$GHOSTFS_SMALL_READ" "$GHOSTFS_LARGE_WRITE" "$GHOSTFS_LARGE_READ"

    printf "  %-16s %11s f/s %11s f/s %11s MB/s %11s MB/s\n" \
        "SSHFS" "$SSHFS_SMALL_WRITE" "$SSHFS_SMALL_READ" "$SSHFS_LARGE_WRITE" "$SSHFS_LARGE_READ"

    printf "  %-16s %11s f/s %11s f/s %11s MB/s %11s MB/s\n" \
        "JuiceFS" "$JUICEFS_SMALL_WRITE" "$JUICEFS_SMALL_READ" "$JUICEFS_LARGE_WRITE" "$JUICEFS_LARGE_READ"

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Calculate and show relative performance
    echo ""
    echo -e "${BOLD}${CYAN}  Relative Performance (vs SSHFS baseline)${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────────${NC}"

    if [ -n "$SSHFS_SMALL_WRITE" ] && [ "$SSHFS_SMALL_WRITE" != "0" ]; then
        GHOSTFS_SW_REL=$(echo "scale=1; $GHOSTFS_SMALL_WRITE / $SSHFS_SMALL_WRITE * 100" | bc 2>/dev/null || echo "N/A")
        JUICEFS_SW_REL=$(echo "scale=1; $JUICEFS_SMALL_WRITE / $SSHFS_SMALL_WRITE * 100" | bc 2>/dev/null || echo "N/A")
        echo -e "  Small Write:  GhostFS ${GHOSTFS_SW_REL}% | SSHFS 100% | JuiceFS ${JUICEFS_SW_REL}%"
    fi

    if [ -n "$SSHFS_SMALL_READ" ] && [ "$SSHFS_SMALL_READ" != "0" ]; then
        GHOSTFS_SR_REL=$(echo "scale=1; $GHOSTFS_SMALL_READ / $SSHFS_SMALL_READ * 100" | bc 2>/dev/null || echo "N/A")
        JUICEFS_SR_REL=$(echo "scale=1; $JUICEFS_SMALL_READ / $SSHFS_SMALL_READ * 100" | bc 2>/dev/null || echo "N/A")
        echo -e "  Small Read:   GhostFS ${GHOSTFS_SR_REL}% | SSHFS 100% | JuiceFS ${JUICEFS_SR_REL}%"
    fi

    if [ -n "$SSHFS_LARGE_WRITE" ] && [ "$SSHFS_LARGE_WRITE" != "0" ]; then
        GHOSTFS_LW_REL=$(echo "scale=1; $GHOSTFS_LARGE_WRITE / $SSHFS_LARGE_WRITE * 100" | bc 2>/dev/null || echo "N/A")
        JUICEFS_LW_REL=$(echo "scale=1; $JUICEFS_LARGE_WRITE / $SSHFS_LARGE_WRITE * 100" | bc 2>/dev/null || echo "N/A")
        echo -e "  Large Write:  GhostFS ${GHOSTFS_LW_REL}% | SSHFS 100% | JuiceFS ${JUICEFS_LW_REL}%"
    fi

    if [ -n "$SSHFS_LARGE_READ" ] && [ "$SSHFS_LARGE_READ" != "0" ]; then
        GHOSTFS_LR_REL=$(echo "scale=1; $GHOSTFS_LARGE_READ / $SSHFS_LARGE_READ * 100" | bc 2>/dev/null || echo "N/A")
        JUICEFS_LR_REL=$(echo "scale=1; $JUICEFS_LARGE_READ / $SSHFS_LARGE_READ * 100" | bc 2>/dev/null || echo "N/A")
        echo -e "  Large Read:   GhostFS ${GHOSTFS_LR_REL}% | SSHFS 100% | JuiceFS ${JUICEFS_LR_REL}%"
    fi

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${DIM}  Note: All filesystems use network protocols over localhost:${NC}"
    echo -e "${DIM}    - GhostFS: Cap'n Proto RPC (port 3444)${NC}"
    echo -e "${DIM}    - SSHFS: SSH/SFTP (port 22)${NC}"
    echo -e "${DIM}    - JuiceFS: S3 via MinIO (port 9000) + Redis metadata${NC}"
    echo -e "${DIM}  ${NC}"
    echo -e "${DIM}  Read tests follow immediately after write tests (warm cache).${NC}"
    echo ""

    # Memory comparison
    echo -e "${BOLD}${CYAN}  Memory Usage Comparison${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────────${NC}"
    printf "  %-16s %12s %12s %12s\n" "Filesystem" "Baseline" "After Bench" "Delta"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────────${NC}"

    GHOSTFS_DELTA=$((${MEM_AFTER_GHOSTFS_GHOSTFS:-0} - ${MEM_BASELINE_GHOSTFS:-0}))
    JUICEFS_DELTA=$((${MEM_AFTER_JUICEFS_JUICEFS:-0} - ${MEM_BASELINE_JUICEFS:-0}))
    SSHFS_DELTA=$((${MEM_AFTER_SSHFS_SSHFS:-0} - ${MEM_BASELINE_SSHFS:-0}))

    printf "  %-16s %10s MB %10s MB %+10s MB\n" \
        "GhostFS" "${MEM_BASELINE_GHOSTFS:-0}" "${MEM_AFTER_GHOSTFS_GHOSTFS:-0}" "$GHOSTFS_DELTA"
    printf "  %-16s %10s MB %10s MB %+10s MB\n" \
        "JuiceFS+MinIO" "${MEM_BASELINE_JUICEFS:-0}" "${MEM_AFTER_JUICEFS_JUICEFS:-0}" "$JUICEFS_DELTA"
    printf "  %-16s %10s MB %10s MB %+10s MB\n" \
        "SSHFS" "${MEM_BASELINE_SSHFS:-0}" "${MEM_AFTER_SSHFS_SSHFS:-0}" "$SSHFS_DELTA"

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Main
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${CYAN}  GhostFS vs Others Benchmark${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${DIM}  Comparing: GhostFS, SSHFS, JuiceFS${NC}"
echo -e "${DIM}  Benchmark: ${SMALL_FILES} small files, ${LARGE_SIZE} MB large file${NC}"
echo ""

# Initialize results
GHOSTFS_SMALL_WRITE=0
GHOSTFS_SMALL_READ=0
GHOSTFS_LARGE_WRITE=0
GHOSTFS_LARGE_READ=0
SSHFS_SMALL_WRITE=0
SSHFS_SMALL_READ=0
SSHFS_LARGE_WRITE=0
SSHFS_LARGE_READ=0
JUICEFS_SMALL_WRITE=0
JUICEFS_SMALL_READ=0
JUICEFS_LARGE_WRITE=0
JUICEFS_LARGE_READ=0

# Start services
start_ssh
start_redis
start_minio
start_ghostfs_server

# Mount filesystems
log_header "Mounting Filesystems"
mount_ghostfs || log_error "GhostFS mount failed, skipping"
mount_sshfs || log_error "SSHFS mount failed, skipping"
mount_juicefs || log_error "JuiceFS mount failed, skipping"

# Run benchmarks
log_header "Running Benchmarks"

# Measure baseline memory before benchmarks
measure_memory "BASELINE"

if ls "$GHOSTFS_MOUNT" &>/dev/null; then
    run_benchmark "GHOSTFS" "$GHOSTFS_MOUNT"
    measure_memory "AFTER_GHOSTFS"
fi

if ls "$SSHFS_MOUNT" &>/dev/null; then
    run_benchmark "SSHFS" "$SSHFS_MOUNT"
    measure_memory "AFTER_SSHFS"
fi

if ls "$JUICEFS_MOUNT" &>/dev/null; then
    run_benchmark "JUICEFS" "$JUICEFS_MOUNT"
    measure_memory "AFTER_JUICEFS"
fi

# Print comparison
print_comparison

log_success "Benchmark complete!"
