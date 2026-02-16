# Devcontainer Dockerfile with pre-installed Claude Code and Playwright
# This caches system packages and tools so rebuilds are faster
# Consolidates devcontainer features into Dockerfile for better layer caching

FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install system packages: Playwright browser dependencies, zsh, and utilities
# Consolidates what was previously in common-utils feature
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Shell and common utilities (from common-utils feature)
    zsh \
    # Core Chromium dependencies
    libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 \
    libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2t64 \
    # Fonts
    fonts-liberation fonts-noto-color-emoji \
    # Playwright host dependencies (recommended)
    libcairo2 libpango-1.0-0 \
    # Utilities used by Claude Code
    bc \
    # Python YAML library for YAML validation
    python3-yaml \
    && rm -rf /var/lib/apt/lists/* \
    # Set zsh as default shell for vscode user
    && chsh -s /usr/bin/zsh vscode

# Install GitHub CLI (from github-cli feature)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js LTS (needed for Claude Code and Playwright)
ARG NODE_VERSION=20
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Install markdown linting tools for documentation quality checks
RUN npm install -g markdownlint-cli markdown-link-check

# Install Playwright browsers to a system-wide path so they survive
# devcontainer feature overlays that may reset /home/vscode.
# This prevents Chrome from being re-downloaded on every container start.
# Pin the version to match the playwright-skill plugin's dependency (^1.57.0)
# to ensure the cached Chromium revision matches what the plugin expects.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
RUN npm install -g playwright@1.58.2 \
    && mkdir -p /opt/playwright-browsers \
    && npx playwright install chromium \
    && chmod -R a+rx /opt/playwright-browsers

# Create directories for vscode user with correct ownership
RUN mkdir -p /home/vscode/.claude/tmp \
    && mkdir -p /home/vscode/.claude/plugins/cache \
    && mkdir -p /home/vscode/.claude/plugins/marketplaces \
    && chown -R vscode:vscode /home/vscode/.claude

# Switch to vscode user for plugin installation
USER vscode
WORKDIR /home/vscode

# Set TMPDIR to avoid EXDEV errors during plugin installation
ENV TMPDIR=/home/vscode/.claude/tmp

# Install playwright-skill plugin
RUN claude plugin marketplace add lackeyjb/playwright-skill \
    && claude plugin install playwright-skill@playwright-skill

# Install Playwright npm dependencies for the plugin (browser already cached above)
RUN cd ~/.claude/plugins/cache/playwright-skill/playwright-skill/*/skills/playwright-skill \
    && npm install

# Switch back to root for any remaining operations
USER root

# --- Future: Uncomment to add Rust toolchain ---
# RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
#     && . /home/vscode/.cargo/env \
#     && rustup component add rustfmt clippy
