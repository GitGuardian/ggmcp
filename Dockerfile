# Multi-stage Dockerfile for GitGuardian MCP Server
# This Dockerfile creates a production-ready container image for the MCP server
#
# Build approach: Builds Python wheels from source, then installs them in production stage.
# This ensures parity between Docker builds and PyPI package distribution.
#
# Base images: Uses GitGuardian's Wolfi-based Python images (Chainguard)
# for improved security posture and minimal attack surface.

FROM ghcr.io/gitguardian/wolfi/python:3.13-dev AS builder

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

# Production stage - Chainguard-based image with shell for build commands
FROM ghcr.io/gitguardian/wolfi/python:3.13-shell

# Switch to root for package installation
USER root

# Copy uv from builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Copy built wheels from builder stage
COPY --from=builder /dist/*.whl /tmp/wheels/

# Copy root package files (for entry point installation)
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY src ./src

# Install all packages from wheels
# Using --system to install globally (not in a venv) since this is a container
# Also install sentry-sdk for error monitoring in production
RUN uv pip install --system /tmp/wheels/*.whl sentry-sdk && \
    rm -rf /tmp/wheels

# Install root package to get entry points (http-mcp-server, etc.)
# This is a metadata-only package that provides entry point scripts
RUN uv pip install --system --no-deps .

# Ensure app directory is owned by nonroot user
RUN chown -R nonroot:nonroot /app

# Switch to nonroot user (UID 65532) for runtime security
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
