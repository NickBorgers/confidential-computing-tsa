#!/bin/bash
set -euo pipefail

# TSA Application Tests
# Usage: test-tsa-application.sh <cvm-core-sha256> <tsa-wrapper-sha256>

CVM_HASH="${1:?Usage: $0 <cvm-core-sha256> <tsa-wrapper-sha256>}"
WRAPPER_HASH="${2:?Usage: $0 <cvm-core-sha256> <tsa-wrapper-sha256>}"
BINARY_DIR="${3:-/home/azureuser}"

PASS=0
FAIL=0

run_test() {
  local name="$1"
  shift
  echo "=== TEST: $name ==="
  if "$@"; then
    echo "PASS: $name"
    ((PASS++))
  else
    echo "FAIL: $name"
    ((FAIL++))
  fi
  echo ""
}

# Test 1: Binary integrity — deployed binaries match CI-computed hashes
test_binary_integrity_cvm() {
  local actual
  actual=$(sha256sum "$BINARY_DIR/cvm-core" | awk '{print $1}')
  echo "  Expected: $CVM_HASH"
  echo "  Actual:   $actual"
  [ "$actual" = "$CVM_HASH" ]
}

test_binary_integrity_wrapper() {
  local actual
  actual=$(sha256sum "$BINARY_DIR/tsa-wrapper" | awk '{print $1}')
  echo "  Expected: $WRAPPER_HASH"
  echo "  Actual:   $actual"
  [ "$actual" = "$WRAPPER_HASH" ]
}

# Test 2: Processes running
test_processes_running() {
  pgrep -x cvm-core > /dev/null && pgrep -x tsa-wrapper > /dev/null
}

# Test 3: Health endpoint
test_health_endpoint() {
  local response
  response=$(curl -sf http://localhost:3000/ 2>/dev/null)
  echo "  Response: $response"
  [ "$response" = '{"status":"healthy"}' ]
}

# Test 4: Timestamp request — POST a valid DER-encoded RFC 3161 TimeStampReq
test_timestamp_request() {
  # Construct a minimal valid DER TimeStampReq:
  #   SEQUENCE {
  #     INTEGER 1 (version)
  #     SEQUENCE { -- messageImprint
  #       SEQUENCE { -- AlgorithmIdentifier
  #         OID 2.16.840.1.101.3.4.2.1 (SHA-256)
  #         NULL
  #       }
  #       OCTET STRING (32 bytes of 0xAA)
  #     }
  #   }
  local hex_req
  # Pre-computed DER encoding of the above structure:
  # SEQUENCE (tag=30, len=3f)
  #   INTEGER 1 (02 01 01)
  #   SEQUENCE messageImprint (30 3a)
  #     SEQUENCE algorithmIdentifier (30 0d)
  #       OID sha256 (06 09 60 86 48 01 65 03 04 02 01)
  #       NULL (05 00)
  #     OCTET STRING 32 bytes (04 20 AA*32)
  hex_req="30410201013039300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000000000"

  # Use printf with octal escapes to create the binary request
  local tmpfile
  tmpfile=$(mktemp)
  echo -n "$hex_req" | xxd -r -p > "$tmpfile"

  # POST to the TSA wrapper
  local http_code response_file
  response_file=$(mktemp)
  http_code=$(curl -s -o "$response_file" -w '%{http_code}' \
    -X POST \
    -H "Content-Type: application/timestamp-query" \
    --data-binary @"$tmpfile" \
    http://localhost:3000/ 2>/dev/null)

  echo "  HTTP status: $http_code"
  echo "  Response size: $(wc -c < "$response_file") bytes"

  # Check HTTP 200
  if [ "$http_code" != "200" ]; then
    echo "  Expected HTTP 200, got $http_code"
    rm -f "$tmpfile" "$response_file"
    return 1
  fi

  # Check response starts with ASN.1 SEQUENCE tag (0x30)
  local first_byte
  first_byte=$(xxd -p -l 1 "$response_file")
  echo "  First byte: 0x$first_byte"
  rm -f "$tmpfile" "$response_file"
  [ "$first_byte" = "30" ]
}

echo "========================================="
echo "TSA Application Tests"
echo "========================================="
echo ""

run_test "cvm-core binary integrity" test_binary_integrity_cvm
run_test "tsa-wrapper binary integrity" test_binary_integrity_wrapper
run_test "TSA processes running" test_processes_running
run_test "Health endpoint responds" test_health_endpoint
run_test "Timestamp request/response" test_timestamp_request

echo "========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Service logs for debugging:"
  echo "--- cvm-core ---"
  cat /tmp/cvm-core.log 2>/dev/null || echo "(no log)"
  echo "--- tsa-wrapper ---"
  cat /tmp/tsa-wrapper.log 2>/dev/null || echo "(no log)"
  exit 1
fi
