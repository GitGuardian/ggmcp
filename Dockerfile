# Multi-stage Dockerfile for GitGuardian MCP Server
# This Dockerfile creates a production-ready container image for the MCP server
#
# Build approach: Builds Python wheels from source, then installs them in production stage.
# This ensures parity between Docker builds and PyPI package distribution.

FROM python:3.13-slim AS builder

# Install uv for fast package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Copy project files needed for building
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY src ./src

# Build wheels for all workspace packages
# This creates distributable .whl files that can be installed anywhere
RUN uv build --package gg-api-core --out-dir /dist && \
    uv build --package developer-mcp-server --out-dir /dist && \
    uv build --package secops-mcp-server --out-dir /dist

# Production stage
FROM python:3.13-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy uv from builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user with UID 65532 (consistent with ward-runs-app)
RUN groupadd -g 65532 nonroot && \
    useradd -u 65532 -g nonroot -m -s /bin/bash nonroot

# Set working directory
WORKDIR /app

# Copy built wheels from builder stage
COPY --from=builder /dist/*.whl /tmp/wheels/

# Copy root package files (for entry point installation)
COPY --chown=65532:65532 pyproject.toml uv.lock README.md ./
COPY --chown=65532:65532 packages ./packages
COPY --chown=65532:65532 src ./src

# Install all packages from wheels
# Using --system to install globally (not in a venv) since this is a container
# Also install sentry-sdk for error monitoring in production
RUN uv pip install --system /tmp/wheels/*.whl sentry-sdk && \
    rm -rf /tmp/wheels

# Install root package to get entry points (http-mcp-server, etc.)
# This is a metadata-only package that provides entry point scripts
RUN uv pip install --system --no-deps .

# Use numeric ID of nonroot, so that security check acknowledges it's not root
USER 65532

# Expose MCP server port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    MCP_PORT=8000 \
    MCP_HOST=0.0.0.0 \
    ENABLE_LOCAL_OAUTH=false

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5.0)" || exit 1

# Empty entrypoint - command is specified in Kubernetes deployment
ENTRYPOINT [""]
