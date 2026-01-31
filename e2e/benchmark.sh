#!/bin/bash
set -e

GHOSTFS="/ghostfs/build/standalone/GhostFS"
ROOT="/data/root"
MOUNT="/mnt/ghostfs"
USER="benchuser"
HOST="127.0.0.1"
PORT="3444"
AUTH_PORT="3445"

mkdir -p "$ROOT/$USER" "$MOUNT"

$GHOSTFS --server --root "$ROOT" --bind "$HOST" --port "$PORT" --auth-port "$AUTH_PORT" &
sleep 3

TOKEN=$($GHOSTFS --authorize --host "$HOST" --auth-port "$AUTH_PORT" --user "$USER" --retries -1 2>&1 | grep -oE '[a-f0-9]{32,}' | head -1)

# Mount with NO read-ahead cache to isolate openAndRead behavior
$GHOSTFS --client --host "$HOST" --port "$PORT" --user "$USER" --token "$TOKEN" \
    --write-back 64 --read-ahead 0 "$MOUNT" &
sleep 3

# Create small files (4KB each - smaller than 64KB prefetch)
echo "Creating 100 small files (4KB each)..."
mkdir -p "$MOUNT/small"
for i in $(seq 1 100); do
    dd if=/dev/urandom of="$MOUNT/small/file_$i.dat" bs=4096 count=1 2>/dev/null
done
sync

echo "Dropping caches..."
echo 3 > /proc/sys/vm/drop_caches

echo "=== Small file read (100 x 4KB) ==="
START=$(date +%s%3N)
for i in $(seq 1 100); do
    cat "$MOUNT/small/file_$i.dat" > /dev/null
done
END=$(date +%s%3N)
MS=$((END - START))
FPS=$(echo "scale=2; 100 * 1000 / $MS" | bc)
echo "Time: ${MS}ms"
echo "Rate: ${FPS} files/s"

echo ""
echo "=== No crash! Small files work. ==="
