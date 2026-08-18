SHELL := /bin/bash
.PHONY: test test-distribution test-vcr test-unit test-with-env test-vcr-with-env update-cassettes lint format typecheck

# =============================================================================
# CI commands (no .env sourcing)
# =============================================================================

# Install/update dependencies from the public PyPI index.
#
# The GitLab private package registry (gitlab.gitguardian.ovh project 435) is
# injected into the shell via the UV_INDEX / PIP_INDEX_URL env vars, and uv's
# precedence (CLI args > env vars > config files) means a repo config file
# cannot override it. We therefore unset those vars here so resolution always
# falls back to the public PyPI index.
sync:
	env -u UV_INDEX -u PIP_INDEX_URL uv sync

# Run all tests
test:
	ENABLE_LOCAL_OAUTH=false uv run pytest

# Run VCR cassette tests only (tests marked with @pytest.mark.vcr_test)
test-vcr:
	ENABLE_LOCAL_OAUTH=false uv run pytest -m vcr_test -v

# Run unit tests (tests NOT marked with @pytest.mark.vcr_test)
test-unit:
	ENABLE_LOCAL_OAUTH=false uv run pytest -m "not vcr_test"

# Build the public artifacts, install the wheel in isolation, and initialize MCP.
test-distribution:
	./scripts/test_distribution.sh

# =============================================================================
# Local dev commands (sources .env for API key)
# =============================================================================

# Run all tests with .env loaded
test-with-env:
	set -a && source .env && set +a && make test

# Run VCR tests with .env loaded (for recording cassettes)
test-vcr-with-env:
	set -a && source .env && set +a && make test-vcr

update-cassettes:
	rm tests/cassettes/client/**/*.yaml && rm tests/cassettes/tools/**/*.yaml && make test-vcr-with-env

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
