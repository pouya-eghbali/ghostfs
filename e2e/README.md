# GhostFS E2E Tests

End-to-end tests for GhostFS using Docker.

## Prerequisites

- Docker
- Docker Compose

## Running Tests

```bash
cd e2e
docker compose up --build --exit-code-from ghostfs
```

## Test Coverage

The e2e tests cover:

1. **File Operations**
   - Create file
   - Read file
   - Write and append
   - Delete file
   - Overwrite file
   - Large file (5MB)

2. **Directory Operations**
   - Create directory
   - List directory
   - Delete directory
   - Nested directories

3. **Advanced Operations**
   - Rename file
   - File permissions
   - Symbolic links
   - File stat
   - Concurrent writes

## Adding New Tests

Add new test functions to `tests/run-e2e.sh` following the existing pattern:

```bash
test_my_new_test() {
    # Setup
    local testfile="$MOUNT/my_test.txt"

    # Action
    echo "test" > "$testfile"

    # Assert
    if [ -f "$testfile" ]; then
        log_pass "My new test"
    else
        log_fail "My new test - description of failure"
    fi
}

# Don't forget to call your test
test_my_new_test
```
