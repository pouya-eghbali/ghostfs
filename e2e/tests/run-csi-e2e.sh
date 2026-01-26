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
CSI_SOCKET="${CSI_SOCKET:-/csi/csi.sock}"
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
    pkill -f "ghostfs.*--csi" 2>/dev/null || true

    sleep 1
}

trap cleanup EXIT

# Setup
log_info "Setting up CSI test environment..."
mkdir -p "$ROOT/$USER"
mkdir -p "$MOUNT"
mkdir -p "$(dirname $CSI_SOCKET)"

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

# Start CSI driver
log_info "Starting CSI driver..."
ghostfs --csi --csi-socket "$CSI_SOCKET" &
CSI_PID=$!
sleep 2

# Check CSI driver is running
if ! kill -0 $CSI_PID 2>/dev/null; then
    log_fail "CSI driver failed to start"
    exit 1
fi
log_info "CSI driver started (PID: $CSI_PID)"

# ============================================================================
# CSI E2E Tests
# ============================================================================

log_info "Running CSI e2e tests..."
echo ""

# Test 1: Identity - GetPluginInfo
test_get_plugin_info() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" csi.v1.Identity/GetPluginInfo 2>&1)

    if echo "$response" | grep -q "ghostfs.csi.k8s.io"; then
        log_pass "GetPluginInfo returns correct plugin name"
    else
        log_fail "GetPluginInfo - unexpected response: $response"
    fi
}

# Test 2: Identity - Probe
test_probe() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" csi.v1.Identity/Probe 2>&1)

    if echo "$response" | grep -q "ready" || [ -z "$response" ] || echo "$response" | grep -q "{}"; then
        log_pass "Probe returns ready"
    else
        log_fail "Probe - unexpected response: $response"
    fi
}

# Test 3: Node - GetCapabilities
test_node_get_capabilities() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" csi.v1.Node/NodeGetCapabilities 2>&1)

    # Empty capabilities is valid for a simple CSI driver
    if [ $? -eq 0 ]; then
        log_pass "NodeGetCapabilities"
    else
        log_fail "NodeGetCapabilities - failed: $response"
    fi
}

# Test 4: Node - GetInfo
test_node_get_info() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" csi.v1.Node/NodeGetInfo 2>&1)

    if echo "$response" | grep -q "nodeId"; then
        log_pass "NodeGetInfo returns node ID"
    else
        log_fail "NodeGetInfo - unexpected response: $response"
    fi
}

# Test 5: NodePublishVolume - Mount a volume
test_node_publish_volume() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" \
        -d "{
            \"volume_id\": \"test-vol-1\",
            \"target_path\": \"$MOUNT\",
            \"volume_capability\": {
                \"mount\": {},
                \"access_mode\": {\"mode\": 5}
            },
            \"volume_context\": {
                \"host\": \"$HOST\",
                \"port\": \"$PORT\",
                \"user\": \"$USER\",
                \"token\": \"$TOKEN\"
            }
        }" \
        csi.v1.Node/NodePublishVolume 2>&1)

    # Give mount time to establish
    sleep 3

    if mountpoint -q "$MOUNT"; then
        log_pass "NodePublishVolume - volume mounted"
    else
        log_fail "NodePublishVolume - mount point not active: $response"
    fi
}

# Test 6: Verify file operations through CSI-mounted volume
test_csi_file_operations() {
    if ! mountpoint -q "$MOUNT"; then
        log_fail "CSI file operations - mount not available"
        return
    fi

    local testfile="$MOUNT/csi_test_file.txt"
    local content="Hello from CSI mount!"

    # Write file
    echo "$content" > "$testfile"

    # Read and verify
    local read_content
    read_content=$(cat "$testfile")

    if [ "$read_content" = "$content" ]; then
        log_pass "CSI file operations - write and read"
    else
        log_fail "CSI file operations - content mismatch: expected '$content', got '$read_content'"
    fi
}

# Test 7: Large file through CSI mount with integrity check
test_csi_large_file_integrity() {
    if ! mountpoint -q "$MOUNT"; then
        log_fail "CSI large file integrity - mount not available"
        return
    fi

    local size_mb=10
    local local_file="/tmp/csi_test_large.bin"
    local ghostfs_file="$MOUNT/csi_large_test.bin"
    local copy_file="/tmp/csi_test_copy.bin"

    # Create random file
    dd if=/dev/urandom of="$local_file" bs=1M count=$size_mb 2>/dev/null

    # Calculate hash
    local hash_original
    hash_original=$(sha256sum "$local_file" | cut -d' ' -f1)

    # Copy to GhostFS via CSI mount
    cp "$local_file" "$ghostfs_file"
    sync

    # Copy back
    cp "$ghostfs_file" "$copy_file"

    # Verify hash
    local hash_copy
    hash_copy=$(sha256sum "$copy_file" | cut -d' ' -f1)

    if [ "$hash_original" = "$hash_copy" ]; then
        log_pass "CSI large file integrity (${size_mb}MB)"
    else
        log_fail "CSI large file integrity - hash mismatch: $hash_original vs $hash_copy"
    fi

    rm -f "$local_file" "$copy_file"
}

# Test 8: NodeUnpublishVolume - Unmount volume
test_node_unpublish_volume() {
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" \
        -d "{
            \"volume_id\": \"test-vol-1\",
            \"target_path\": \"$MOUNT\"
        }" \
        csi.v1.Node/NodeUnpublishVolume 2>&1)

    # Give unmount time to complete
    sleep 2

    if ! mountpoint -q "$MOUNT"; then
        log_pass "NodeUnpublishVolume - volume unmounted"
    else
        log_fail "NodeUnpublishVolume - mount point still active: $response"
    fi
}

# Test 9: Remount and verify data persistence
test_csi_data_persistence() {
    # Mount again
    local response
    response=$(grpcurl -plaintext -unix "$CSI_SOCKET" \
        -d "{
            \"volume_id\": \"test-vol-2\",
            \"target_path\": \"$MOUNT\",
            \"volume_capability\": {
                \"mount\": {},
                \"access_mode\": {\"mode\": 5}
            },
            \"volume_context\": {
                \"host\": \"$HOST\",
                \"port\": \"$PORT\",
                \"user\": \"$USER\",
                \"token\": \"$TOKEN\"
            }
        }" \
        csi.v1.Node/NodePublishVolume 2>&1)

    sleep 3

    if ! mountpoint -q "$MOUNT"; then
        log_fail "CSI data persistence - failed to remount"
        return
    fi

    # Check if previous test file still exists
    local testfile="$MOUNT/csi_test_file.txt"
    if [ -f "$testfile" ]; then
        local content
        content=$(cat "$testfile")
        if [ "$content" = "Hello from CSI mount!" ]; then
            log_pass "CSI data persistence - file preserved after remount"
        else
            log_fail "CSI data persistence - file content changed"
        fi
    else
        log_fail "CSI data persistence - file not found after remount"
    fi

    # Cleanup: unmount
    grpcurl -plaintext -unix "$CSI_SOCKET" \
        -d "{
            \"volume_id\": \"test-vol-2\",
            \"target_path\": \"$MOUNT\"
        }" \
        csi.v1.Node/NodeUnpublishVolume 2>&1 >/dev/null
    sleep 2
}

# Run all tests (disable set -e so test failures don't abort)
set +e

# Identity service tests
test_get_plugin_info
test_probe

# Node service tests
test_node_get_capabilities
test_node_get_info

# Volume lifecycle tests
test_node_publish_volume
test_csi_file_operations
test_csi_large_file_integrity
test_node_unpublish_volume
test_csi_data_persistence

set -e

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "============================================"
echo -e "CSI Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "CSI Tests failed: ${RED}$TESTS_FAILED${NC}"
echo "============================================"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi

exit 0
