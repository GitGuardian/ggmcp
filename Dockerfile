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
COPY pyproject.toml uv.lock ./
COPY packages ./packages

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

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash mcpserver

# Set working directory
WORKDIR /app

# Copy built wheels from builder stage
COPY --from=builder /dist/*.whl /tmp/wheels/

# Install all packages from wheels
# Using --system to install globally (not in a venv) since this is a container
RUN uv pip install --system /tmp/wheels/*.whl && \
    rm -rf /tmp/wheels

# Switch to non-root user
USER mcpserver

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

# Default to secops server, can be overridden
CMD ["secops-mcp-server"]
