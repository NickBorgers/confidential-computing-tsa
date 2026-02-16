#!/bin/bash
set -euo pipefail

# Start CVM core in background (signing oracle on 127.0.0.1:5000)
cvm-core &
CVM_PID=$!

# Wait for CVM core to be ready
echo "Waiting for cvm-core on port 5000..."
for i in $(seq 1 30); do
  if bash -c 'echo > /dev/tcp/127.0.0.1/5000' 2>/dev/null; then
    echo "cvm-core ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "TIMEOUT: cvm-core did not start"
    exit 1
  fi
  sleep 1
done

# Exec wrapper in foreground (HTTP server on 0.0.0.0:3000)
exec tsa-wrapper
