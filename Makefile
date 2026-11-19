SHELL := /bin/bash
.PHONY: test test-with-env lint format typecheck

# =============================================================================
# CI commands (no .env sourcing)
# =============================================================================

# Run all tests
test:
	ENABLE_LOCAL_OAUTH=false uv run pytest

# =============================================================================
# Local dev commands (sources .env)
# =============================================================================

# Run all tests with .env loaded
test-with-env:
	set -a && source .env && set +a && make test

# =============================================================================
# Code quality
# =============================================================================

# Linting
lint:
	uv run ruff check .

# Format code
format:
	uv run ruff format .

# Type checking
typecheck:
	uv run pyrefly check
