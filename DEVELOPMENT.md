# Development Guide

This document provides instructions for developers who want to contribute to the GG MCP Server project.

## Environment Setup

1. Install Python 3.13 or higher
2. Install [uv](https://github.com/astral-sh/uv) (required for package management)
3. Clone the repository:
   ```bash
   git clone https://github.com/GitGuardian/ggmcp.git
   cd ggmcp
   ```
4. Install dependencies:
   ```bash
   uv sync --dev
   ```
5. Install pre-commit hooks:
   ```bash
   pre-commit install && pre-commit install --hook-type pre-push
   ```

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to ensure code quality and security standards. The hooks are
configured in `.pre-commit-config.yaml` and include:

**On every commit:**

- **Ruff** - Automatically lints and formats Python code
- **Commitizen** - Validates commit message format
- **GitGuardian ggshield** - Scans for secrets in staged files

**On every push:**

- **Commitizen-branch** - Validates branch naming conventions
- **GitGuardian ggshield-push** - Scans all commits being pushed for secrets

The hooks will automatically run before commits/pushes and will block the operation if any issues are found. You can
also run the hooks manually:

```bash
# Run all hooks on all files
pre-commit run --all-files

# Run a specific hook
pre-commit run ruff --all-files
```

## Project Structure

- `src/gg_api_core/client.py`: the GitGuardian API client.
- `src/gg_api_core/tools/`: one module per tool, each with a pydantic params model.
- `src/gg_mcp_server/register_tools.py`: registers every tool with its `required_scopes`.
- `tests/e2e/`: end-to-end tests that pin the request each tool sends to the API and the output it returns.

## Adding a New Tool

1. Add the tool function and its params model in `src/gg_api_core/tools/`.
2. Register it in `src/gg_mcp_server/register_tools.py` with its `required_scopes`. If it needs a scope
   that `DEFAULT_SCOPES` in `src/gg_api_core/scopes.py` lacks, add it there, or new tokens won't see the tool.
3. Add e2e tests in `tests/e2e/` for the API request and the tool output.

## Authentication Modes

The server picks an authentication mode based on env vars and transport.
User-facing details live in the project README; this section is for
contributors who need to know how the selection happens internally.

### OAuth proxy (HTTP, recommended)

Set `MCP_OAUTH_PROXY_ENABLED=true`, `MULTI_TENANCY_ENABLED=true` and `MCP_PORT`
on an HTTP deployment. The server
advertises OAuth Protected Resource metadata (RFC 9728) and proxies
`/authorize`, `/token`, `/register` to the GG dashboard. MCP clients run
the OAuth flow themselves and send `Authorization: Bearer <PAT>` on every
request. This is what the hosted server at `mcp.gitguardian.com` runs.

### Per-request bearer (HTTP fallback)

When `ENABLE_LOCAL_OAUTH=false`, `MULTI_TENANCY_ENABLED=true`, `MCP_PORT` is set
and `MCP_OAUTH_PROXY_ENABLED` is unset, clients pass `Authorization: Bearer <PAT>`
directly and the server forwards it verbatim. Used by raw HTTP integrations.

Both HTTP modes need `MULTI_TENANCY_ENABLED=true`: without it, `get_client()`
ignores the request's token and looks for a single server-wide one.

### PAT environment variable (any transport)

```bash
GITGUARDIAN_PERSONAL_ACCESS_TOKEN=<your-pat> gg-mcp-server
```

The server uses the PAT for every GitGuardian API call. Useful for CI,
scripts, and the recommended path for local stdio.

### Local OAuth flow (stdio, deprecated)

The legacy `ENABLE_LOCAL_OAUTH=true` flow in stdio opens a browser and
runs a localhost callback on a port in 29170-29998, storing the PAT under
`~/Library/Application Support/GitGuardian/` (macOS) or
`$XDG_CONFIG_HOME/gitguardian/` (Linux). This mode is deprecated; new
stdio deployments should use a PAT. The code path will be removed in a
future release.

## Logging

Structured logging goes to stderr via structlog. `LOG_LEVEL` sets the level and
`LOG_FORMAT` picks `json` or `console` (unset auto-detects: console on a TTY).
`gg_api_core/logging_config.py` owns the processor chain.

### Fields on every line

Bound once per MCP message by `RequestLoggingContextMiddleware`, so they ride on
every line emitted while handling it, including free-text lines from libraries.

| Field | Meaning |
| --- | --- |
| `gg_service`, `gg_version` | Which service and which release produced the line |
| `request_id` | Inbound `X-Request-ID`, or one generated per message |
| `mcp_session_id` | FastMCP's session id. Groups a conversation **only if** the client sends a stable `Mcp-Session-Id`; under `stateless_http=True` it is otherwise per-request |
| `user_agent` | The only client hint present on every request |
| `authentication_mode` | How the request authenticates: OAuth proxy, authorization header, environment PAT, or local OAuth |
| `account_id`, `workspace_id`, `member_id` | Which customer and which user. `account_id` aliases the GitGuardian API's `workspace_id` for cross-service observability |
| `token_id`, `token_type`, `token_scopes_hash` | Which credential, and a digest of its scope set. Never the token itself |
| `gg_host` | Separates SaaS from self-hosted; the same workspace id can exist on both |

### Events

| Event | When | Notable fields |
| --- | --- | --- |
| `tool_call` / `tool_call_failed` | Per tool invocation | `tool`, `arguments`, `duration_ms`, `result_bytes`, `result_items`, `truncated`, `downstream_calls`, `downstream_ms`, `downstream_retries`, `downstream_wait_ms`, and on failure `error_class`, `upstream_status`, `gg_error_code`, `fault` |
| `mcp_request` / `mcp_request_failed` | Per protocol message except `tools/call` | `mcp_method`, `status`, `duration_ms` |
| `mcp_initialize` | Handshake | `client_name`, `client_version`, `protocol_version` |
| `list_tools` | Scope filtering | `tools_exposed`, `tools_hidden`, `hidden_tools` |
| `api_request` | Per outbound GitGuardian API call | `method`, `path` (templated), `status`, `duration_ms`, `gg_request_id` |
| `pagination_complete` | End of a paginated fetch | `items`, `response_bytes`, `truncated`, `pages` |
| `oauth_step` | Each step of the OAuth proxy funnel | `oauth_step`, `outcome`, `status` |

`fault` grades who has to act: `client` for bad input or a missing permission,
`server` for anything worth paging about. Filter on it before reading a failure
list. 408 and 429 count as server fault.

`downstream_ms` includes retry backoff, so `duration_ms - downstream_ms` is time
that was genuinely ours. `downstream_wait_ms` breaks out the backoff portion.
Counters and `truncated` are emitted even at zero and false, so a rate has a
denominator.

`gg_error_code` carries only machine-readable `code`/`error` values, never
DRF's `detail` prose, which on scan endpoints can echo the submitted payload.

`ping` is answered by the low-level MCP SDK before FastMCP dispatches, so no
middleware hook sees it and it produces no event.

### Redaction

`gg_api_core/sanitization.py` scrubs by field name and by value. When adding a
field whose name contains a token like `token` or `content` but which carries no
secret, add it to `NON_SENSITIVE_NAME_ALLOWLIST`, otherwise it renders as
`[REDACTED]`.

Sentry's `MCPIntegration` is the sole capture owner for tool exceptions.
`LoggingIntegration` records INFO-and-higher lines as breadcrumbs but has event
capture disabled, so client, tool, FastMCP, and middleware error logs cannot
create duplicate issues.

Sentry payloads are scrubbed at the SDK boundary. `before_breadcrumb` applies
field-name redaction inside logging `data` and value redaction to the complete
breadcrumb. `before_send` value-scrubs the finished event, including exception
values and request data added by Sentry itself. Name-based redaction is not
applied to the whole event because Sentry schema keys such as `filename` and
`module` would destroy the stack trace. `include_local_variables=False` keeps
frame locals out of the payload entirely.

## Optional Dependencies

The project supports optional dependencies (extras) for additional features:

### Installing Optional Dependencies

```bash
# Install with specific extras during development
uv sync --extra sentry

# Install all optional dependencies
uv sync --all-extras

# Add an optional dependency to the project
uv add --optional sentry sentry-sdk
```

### Using Optional Dependencies with uvx

When running the server with `uvx` from Git, you can include optional dependencies:

```bash
# Include extras by naming the distribution
uvx --from 'ggmcp[sentry] @ git+https://github.com/GitGuardian/ggmcp.git@main' gg-mcp-server

# Or install the optional dependency separately
uv pip install sentry-sdk
uvx --from git+https://github.com/GitGuardian/ggmcp.git@main gg-mcp-server
```

### Current Optional Dependencies

- **sentry**: Adds the Sentry SDK for error tracking
  - Core package: `gg-api-core[sentry]`
  - Available in: `gg-mcp-server[sentry]`
  - Implementation: `src/gg_api_core/sentry_integration.py`
  - Used for: MCP exception capture, sanitized breadcrumbs, monitoring, and alerting

## Testing

Run tests using uv (OAuth is disabled by default in tests):

```bash
ENABLE_LOCAL_OAUTH=false uv run pytest
```

Run tests with verbose output:

```bash
ENABLE_LOCAL_OAUTH=false uv run pytest -v
```

Create test files in the `tests/` directory that match the pattern `test_*.py`.

## Code Style

This project uses `ruff` for linting and formatting. While pre-commit hooks will automatically run ruff on your staged
files, you can also run it manually:

```bash
# Check for linting issues
ruff check src tests

# Auto-fix linting issues
ruff check --fix src tests

# Format code
ruff format src tests
```

**Note:** Pre-commit hooks will automatically run ruff on your staged files when you commit, so you usually don't need
to run it manually.

## Documentation

When adding a new tool, list it under "What it does" in `README.md`. When removing one, add it to the README's
"Migration notes".

## Pull Request Process

1. Create a new branch for your feature or fix (ensure it follows the naming convention enforced by commitizen-branch)
2. Make your changes, adding tests and documentation
3. Ensure all tests pass and linting issues are fixed
4. Commit your changes with properly formatted commit messages (enforced by commitizen pre-commit hook)
5. Push your changes (pre-push hooks will scan for secrets and validate branch names)
6. Submit a pull request with a clear description of your changes

**Note:** The pre-commit and pre-push hooks will automatically check your code quality, commit messages, and scan for
secrets before allowing commits and pushes.

## Releasing

Releases are automated with release-please and driven by conventional
commits. Never bump versions by hand: release-please maintains a rolling
`chore(main): release X.Y.Z` PR, and merging that PR tags `vX.Y.Z` and
publishes the Docker image (`X.Y.Z`, `X.Y`, `latest`). Ordinary merges only
refresh the `main` and `main-<sha>-<seq>` image tags. See `PUBLISHING.md`
for details and the manual escape hatch.
