#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ROOT="${GHOSTFS_ROOT:-/data/root}"
MOUNT="${GHOSTFS_MOUNT:-/mnt/ghostfs}"
HOST="${GHOSTFS_HOST:-127.0.0.1}"
PORT="${GHOSTFS_PORT:-3444}"
AUTH_PORT="${GHOSTFS_AUTH_PORT:-3445}"
USER="testuser"
TOKEN=""

TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
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

    sleep 1
}

trap cleanup EXIT

# Setup
log_info "Setting up test environment..."
mkdir -p "$ROOT/$USER"
mkdir -p "$MOUNT"

# Start the server in background
log_info "Starting GhostFS server..."
ghostfs --server --root "$ROOT" --bind "$HOST" --port "$PORT" --auth-port "$AUTH_PORT" &
SERVER_PID=$!
sleep 2

# Check server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    log_fail "Server failed to start"
    exit 1
fi
log_info "Server started (PID: $SERVER_PID)"

# Add a token for the test user
log_info "Adding authentication token..."
TOKEN=$(ghostfs --authorize --host "$HOST" --auth-port "$AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)

if [ -z "$TOKEN" ]; then
    log_fail "Failed to get authentication token"
    exit 1
fi
log_info "Got token: $TOKEN"

# Mount the filesystem with large cache settings for integrity testing
log_info "Mounting GhostFS client..."
ghostfs --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
    --write-back 32 --read-ahead 32 "$MOUNT" &
CLIENT_PID=$!
sleep 2

# Check if mounted
if ! mountpoint -q "$MOUNT"; then
    log_fail "Failed to mount filesystem"
    exit 1
fi
log_info "Filesystem mounted at $MOUNT"

# ============================================================================
# E2E Tests
# ============================================================================

log_info "Running e2e tests..."
echo ""

# Test 1: Create a file
test_create_file() {
    local testfile="$MOUNT/test_create.txt"
    local content="Hello, GhostFS!"

    echo "$content" > "$testfile"

    if [ -f "$testfile" ]; then
        log_pass "Create file"
    else
        log_fail "Create file - file not found after creation"
    fi
}

# Test 2: Read a file
test_read_file() {
    local testfile="$MOUNT/test_read.txt"
    local content="Test content for reading"

    echo "$content" > "$testfile"
    local read_content=$(cat "$testfile")

    if [ "$read_content" = "$content" ]; then
        log_pass "Read file"
    else
        log_fail "Read file - content mismatch: expected '$content', got '$read_content'"
    fi
}

# Test 3: Write and append to file
test_write_append() {
    local testfile="$MOUNT/test_append.txt"

    echo "Line 1" > "$testfile"
    echo "Line 2" >> "$testfile"

    local lines=$(wc -l < "$testfile")

    if [ "$lines" -eq 2 ]; then
        log_pass "Write and append"
    else
        log_fail "Write and append - expected 2 lines, got $lines"
    fi
}

# Test 4: Create directory
test_create_directory() {
    local testdir="$MOUNT/test_dir"

    mkdir -p "$testdir"

    if [ -d "$testdir" ]; then
        log_pass "Create directory"
    else
        log_fail "Create directory - directory not found"
    fi
}

# Test 5: List directory
test_list_directory() {
    local testdir="$MOUNT/test_listdir"
    mkdir -p "$testdir"
    touch "$testdir/file1.txt"
    touch "$testdir/file2.txt"
    touch "$testdir/file3.txt"

    local count=$(ls "$testdir" | wc -l)

    if [ "$count" -eq 3 ]; then
        log_pass "List directory"
    else
        log_fail "List directory - expected 3 files, got $count"
    fi
}

# Test 6: Delete file
test_delete_file() {
    local testfile="$MOUNT/test_delete.txt"

    touch "$testfile"
    rm "$testfile"

    if [ ! -f "$testfile" ]; then
        log_pass "Delete file"
    else
        log_fail "Delete file - file still exists"
    fi
}

# Test 7: Delete directory
test_delete_directory() {
    local testdir="$MOUNT/test_rmdir"

    mkdir -p "$testdir"
    rmdir "$testdir"

    if [ ! -d "$testdir" ]; then
        log_pass "Delete directory"
    else
        log_fail "Delete directory - directory still exists"
    fi
}

# Test 8: Rename file
test_rename_file() {
    local oldname="$MOUNT/test_rename_old.txt"
    local newname="$MOUNT/test_rename_new.txt"

    echo "rename test" > "$oldname"
    mv "$oldname" "$newname"

    if [ ! -f "$oldname" ] && [ -f "$newname" ]; then
        log_pass "Rename file"
    else
        log_fail "Rename file - rename failed"
    fi
}

# Test 9: File permissions
test_file_permissions() {
    local testfile="$MOUNT/test_perms.txt"

    touch "$testfile"
    chmod 755 "$testfile"

    local perms=$(stat -c "%a" "$testfile" 2>/dev/null || stat -f "%Lp" "$testfile" 2>/dev/null)

    if [ "$perms" = "755" ]; then
        log_pass "File permissions"
    else
        log_fail "File permissions - expected 755, got $perms"
    fi
}

# Test 10: Large file write/read
test_large_file() {
    local testfile="$MOUNT/test_large.bin"
    local size_mb=5

    # Create a 5MB file
    dd if=/dev/urandom of="$testfile" bs=1M count=$size_mb 2>/dev/null

    local actual_size=$(stat -c "%s" "$testfile" 2>/dev/null || stat -f "%z" "$testfile" 2>/dev/null)
    local expected_size=$((size_mb * 1024 * 1024))

    if [ "$actual_size" -eq "$expected_size" ]; then
        log_pass "Large file ($size_mb MB)"
    else
        log_fail "Large file - expected $expected_size bytes, got $actual_size"
    fi
}

# Test 11: Symbolic link
test_symlink() {
    local target="$MOUNT/symlink_target.txt"
    local link="$MOUNT/symlink_link.txt"

    echo "symlink target" > "$target"

    # Symlink with timeout (may hang on some FUSE implementations)
    if timeout 5 ln -s "$target" "$link" 2>/dev/null; then
        if [ -L "$link" ]; then
            local content=$(timeout 5 cat "$link" 2>/dev/null)
            if [ "$content" = "symlink target" ]; then
                log_pass "Symbolic link"
            else
                log_fail "Symbolic link - content mismatch through link"
            fi
        else
            log_fail "Symbolic link - link not created"
        fi
    else
        log_fail "Symbolic link - operation timed out or failed"
    fi
}

# Test 12: Nested directories
test_nested_directories() {
    local nested="$MOUNT/level1/level2/level3"

    mkdir -p "$nested"
    touch "$nested/deep_file.txt"

    if [ -f "$nested/deep_file.txt" ]; then
        log_pass "Nested directories"
    else
        log_fail "Nested directories - deep file not found"
    fi
}

# Test 13: File stat
test_file_stat() {
    local testfile="$MOUNT/test_stat.txt"
    echo "stat test" > "$testfile"

    if stat "$testfile" > /dev/null 2>&1; then
        log_pass "File stat"
    else
        log_fail "File stat - stat command failed"
    fi
}

# Test 14: Concurrent writes
test_concurrent_writes() {
    local testdir="$MOUNT/concurrent"
    mkdir -p "$testdir"

    # Create 10 files concurrently with slight staggering to avoid connection thundering herd
    for i in $(seq 1 10); do
        echo "content $i" > "$testdir/file$i.txt" &
        # Small delay between spawns to stagger connection establishment
        sleep 0.05
    done

    # Wait with timeout (safety net for CI environment)
    if timeout 60 bash -c 'wait'; then
        local count=$(ls "$testdir" 2>/dev/null | wc -l)

        if [ "$count" -eq 10 ]; then
            log_pass "Concurrent writes"
        else
            log_fail "Concurrent writes - expected 10 files, got $count"
        fi
    else
        log_fail "Concurrent writes - timed out"
    fi
}

# Test 15: Overwrite file
test_overwrite_file() {
    local testfile="$MOUNT/test_overwrite.txt"

    echo "original content" > "$testfile"
    echo "new content" > "$testfile"

    local content=$(cat "$testfile")

    if [ "$content" = "new content" ]; then
        log_pass "Overwrite file"
    else
        log_fail "Overwrite file - content not updated"
    fi
}

# Test 16: Large file integrity with hash verification (32MB)
# Tests readahead/writeback cache integrity by:
# 1. Creating a random file locally
# 2. Copying to GhostFS and verifying hash
# 3. Copying back from GhostFS and verifying hash
test_large_file_integrity() {
    local size_mb=32
    local local_original="/tmp/test_integrity_original.bin"
    local ghostfs_file="$MOUNT/test_integrity.bin"
    local local_copy="/tmp/test_integrity_copy.bin"

    log_info "Creating ${size_mb}MB random file for integrity test..."

    # Create random file locally
    dd if=/dev/urandom of="$local_original" bs=1M count=$size_mb 2>/dev/null

    # Calculate hash of original
    local hash_original=$(sha256sum "$local_original" | cut -d' ' -f1)
    log_info "Original hash: $hash_original"

    # Copy to GhostFS
    log_info "Copying to GhostFS..."
    cp "$local_original" "$ghostfs_file"

    # Sync to ensure all writes are flushed
    sync

    # Calculate hash of file on GhostFS
    local hash_ghostfs=$(sha256sum "$ghostfs_file" | cut -d' ' -f1)
    log_info "GhostFS hash: $hash_ghostfs"

    # Copy back from GhostFS
    log_info "Copying back from GhostFS..."
    cp "$ghostfs_file" "$local_copy"

    # Calculate hash of copied file
    local hash_copy=$(sha256sum "$local_copy" | cut -d' ' -f1)
    log_info "Copy hash: $hash_copy"

    # Clean up temp files
    rm -f "$local_original" "$local_copy"

    # Verify all hashes match
    if [ "$hash_original" = "$hash_ghostfs" ] && [ "$hash_ghostfs" = "$hash_copy" ]; then
        log_pass "Large file integrity (${size_mb}MB, SHA256 verified)"
    else
        log_fail "Large file integrity - hash mismatch:"
        log_fail "  Original: $hash_original"
        log_fail "  GhostFS:  $hash_ghostfs"
        log_fail "  Copy:     $hash_copy"
    fi
}

# Run all tests (disable set -e so test failures don't abort)
set +e
test_create_file
test_read_file
test_write_append
test_create_directory
test_list_directory
test_delete_file
test_delete_directory
test_rename_file
test_file_permissions
test_large_file
test_symlink
test_nested_directories
test_file_stat
test_concurrent_writes
test_overwrite_file
test_large_file_integrity
set -e

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "============================================"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo "============================================"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi

exit 0
