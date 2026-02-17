#!/bin/bash
set -euo pipefail

BINARY_DIR="${1:-/home/azureuser}"

echo "=== Deploying TSA binaries ==="

# Make binaries executable
chmod +x "$BINARY_DIR/cvm-core" "$BINARY_DIR/tsa-wrapper"

# Start CVM core (signing oracle on 127.0.0.1:5000)
echo "Starting cvm-core..."
nohup "$BINARY_DIR/cvm-core" > /tmp/cvm-core.log 2>&1 &
CVM_PID=$!
echo "cvm-core started (PID $CVM_PID)"

# Wait for CVM core to be ready on TCP 5000
echo "Waiting for cvm-core on port 5000..."
for i in $(seq 1 30); do
  if bash -c 'echo > /dev/tcp/127.0.0.1/5000' 2>/dev/null; then
    echo "cvm-core ready (attempt $i)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "TIMEOUT: cvm-core did not become ready"
    echo "cvm-core log:"
    cat /tmp/cvm-core.log
    exit 1
  fi
  sleep 1
done

# Start TSA wrapper (HTTP server on 0.0.0.0:3000)
echo "Starting tsa-wrapper..."
nohup "$BINARY_DIR/tsa-wrapper" > /tmp/tsa-wrapper.log 2>&1 &
WRAPPER_PID=$!
echo "tsa-wrapper started (PID $WRAPPER_PID)"

# Wait for wrapper to be ready on TCP 3000
echo "Waiting for tsa-wrapper on port 3000..."
for i in $(seq 1 30); do
  if bash -c 'echo > /dev/tcp/127.0.0.1/3000' 2>/dev/null; then
    echo "tsa-wrapper ready (attempt $i)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "TIMEOUT: tsa-wrapper did not become ready"
    echo "tsa-wrapper log:"
    cat /tmp/tsa-wrapper.log
    exit 1
  fi
  sleep 1
done

# Write sentinel file
touch /tmp/tsa-deploy-complete
echo "=== TSA deployment complete ==="
echo "cvm-core PID: $CVM_PID (127.0.0.1:5000)"
echo "tsa-wrapper PID: $WRAPPER_PID (0.0.0.0:3000)"
