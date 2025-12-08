SHELL := /bin/bash
.PHONY: test test-vcr test-unit test-with-env test-vcr-with-env lint format typecheck

# =============================================================================
# CI commands (no .env sourcing)
# =============================================================================

# Run all tests
test:
	ENABLE_LOCAL_OAUTH=false uv run pytest

# Run VCR cassette tests only (tests marked with @pytest.mark.vcr_test)
test-vcr:
	ENABLE_LOCAL_OAUTH=false uv run pytest -m vcr_test -v

# Run unit tests (tests NOT marked with @pytest.mark.vcr_test)
test-unit:
	ENABLE_LOCAL_OAUTH=false uv run pytest -m "not vcr_test"

# =============================================================================
# Local dev commands (sources .env for API key)
# =============================================================================

# Run all tests with .env loaded
test-with-env:
	set -a && source .env && set +a && make test

# Run VCR tests with .env loaded (for recording cassettes)
test-vcr-with-env:
	set -a && source .env && set +a && make test-vcr

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
	uv run mypy .
