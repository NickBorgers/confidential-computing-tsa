#!/bin/bash
# Post-create setup script for devcontainer
# This script runs automatically when the devcontainer is created

set -e

echo "=== Setting up devcontainer ==="

# Fix DNS order to prioritize Tailscale MagicDNS
# (Also runs via postStartCommand on every container start)
echo "Checking DNS configuration..."
bash "$(dirname "$0")/fix-dns-order.sh"

# Compute repository root (parent of .devcontainer) so script works
# regardless of the local workspace folder name.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Set up Rust project dependencies
echo "Setting up Rust project... (repo root: $REPO_ROOT)"
if [ -f "$REPO_ROOT/Cargo.toml" ]; then
    (cd "$REPO_ROOT" && cargo fetch)
else
    echo "Warning: $REPO_ROOT/Cargo.toml not found; skipping cargo fetch."
fi

# Git hooks
echo "Installing git hooks..."
if [ -d "$REPO_ROOT" ]; then
    if [ -x "$REPO_ROOT/.githooks/install-hooks.sh" ] || [ -f "$REPO_ROOT/.githooks/install-hooks.sh" ]; then
        (cd "$REPO_ROOT" && bash .githooks/install-hooks.sh)
    else
        echo "Warning: .githooks/install-hooks.sh not found or not executable; skipping git hooks installation."
    fi
else
    echo "Warning: repository root $REPO_ROOT not found; skipping git hooks installation."
fi

# Note: Claude Code and playwright-skill plugin are now pre-installed
# in the Dockerfile for faster rebuilds via Docker layer caching.
# Chromium is cached at /opt/playwright-browsers (set via PLAYWRIGHT_BROWSERS_PATH)
# to survive devcontainer feature overlays on /home/vscode.

# Verify Playwright browser is available (should be pre-installed in Docker image)
if [ -n "$PLAYWRIGHT_BROWSERS_PATH" ] && [ -d "$PLAYWRIGHT_BROWSERS_PATH" ]; then
    CHROMIUM_DIRS=$(find "$PLAYWRIGHT_BROWSERS_PATH" -maxdepth 1 -name 'chromium-*' -type d 2>/dev/null)
    if [ -n "$CHROMIUM_DIRS" ]; then
        echo "Playwright Chromium already installed at $PLAYWRIGHT_BROWSERS_PATH (skipping download)"
    else
        echo "Warning: Chromium not found in $PLAYWRIGHT_BROWSERS_PATH; installing..."
        npx playwright install chromium
    fi
else
    echo "Warning: PLAYWRIGHT_BROWSERS_PATH not set; Chromium will be downloaded on first use"
fi

echo "=== Devcontainer setup complete ==="
