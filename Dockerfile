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
COPY src ./src

# Build the single distribution wheel (import packages gg_api_core and gg_mcp_server)
RUN uv build --wheel --out-dir /dist

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

# Lockfile used to export the exact dependency set
COPY pyproject.toml uv.lock README.md ./

# `uv pip install <wheel>` ignores uv.lock and re-resolves the wheel's `~=` ranges at build
# time, so rebuilds drift. Install the locked deps instead, then the wheel with --no-deps.
# The sentry extra adds sentry-sdk for prod monitoring.
RUN uv export --frozen --no-dev --no-emit-project --extra sentry \
        --format requirements-txt -o /tmp/requirements.txt && \
    uv pip install --system --require-hashes -r /tmp/requirements.txt && \
    uv pip install --system --no-deps /tmp/wheels/*.whl && \
    rm -rf /tmp/wheels /tmp/requirements.txt

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
