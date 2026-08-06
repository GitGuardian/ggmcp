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

```
ggmcp/
├── src/
│   ├── server.py            # Main MCP server entry point
│   ├── gitguardian/         # GitGuardian Honeytoken tool
│   │   ├── __init__.py
│   │   ├── client.py        # API client for GitGuardian
│   │   └── tools.py         # Tool implementation
│   └── [other_tools]/       # Additional tools will be added here
├── tests/                   # Test suite
│   ├── test_gitguardian_client.py
│   └── ...
├── pyproject.toml           # Project configuration and dependencies
├── README.md                # Main documentation
└── DEVELOPMENT.md           # This file
```

## Adding a New Tool

To add a new tool to the MCP server:

1. Create a new directory in `src/` for your tool
2. Implement your tool following the MCP Tools specification
3. Register your tool in `src/server.py`
4. Add unit tests for your tool
5. Update the README.md to document your tool

### Example Tool Structure

```python
# src/example/tools.py
from fastmcp import Request, Response, Tool
from typing import Dict, Any


class ExampleTool(Tool):
    """Example tool implementation."""

    def __init__(self):
        """Initialize the tool."""
        pass

    def schema(self) -> Dict[str, Any]:
        """Define the schema for the tool."""
        return {
            "name": "example_tool",
            "description": "Example tool description",
            "parameters": {
                "type": "object",
                "required": ["param1"],
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "First parameter"
                    }
                }
            }
        }

    async def execute(self, request: Request) -> Response:
        """Execute the tool."""
        param1 = request.data.get("param1")

        result = f"Processed: {param1}"

        return Response(
            status="success",
            data={"result": result}
        )


# List of tools to be exported
tools = [ExampleTool()]
```

Then register the tool in `src/server.py`:

```python
# src/server.py
from example.tools import tools as example_tools

# Register the tools
for tool in example_tools:
    mcp.tool(tool)
```

## Authentication Modes

The server picks an authentication mode based on env vars and transport.
User-facing details live in the project README; this section is for
contributors who need to know how the selection happens internally.

### OAuth proxy (HTTP, recommended)

Set `MCP_OAUTH_PROXY_ENABLED=true` on an HTTP deployment. The server
advertises OAuth Protected Resource metadata (RFC 9728) and proxies
`/authorize`, `/token`, `/register` to the GG dashboard. MCP clients run
the OAuth flow themselves and send `Authorization: Bearer <PAT>` on every
request. This is what the hosted server at `mcp.gitguardian.com` runs.

### Per-request bearer (HTTP fallback)

When `ENABLE_LOCAL_OAUTH=false` and `MCP_OAUTH_PROXY_ENABLED` is unset on
HTTP, clients pass `Authorization: Bearer <PAT>` directly; the server
forwards verbatim. Used by raw HTTP integrations and the production Helm
chart's gunicorn target.

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
| `tool_call` / `tool_call_failed` | Per tool invocation | `tool`, `arguments`, `elapsed_ms`, `result_bytes`, `result_items`, `truncated`, `downstream_calls`, `downstream_ms`, `downstream_retries`, `downstream_wait_ms`, and on failure `error_class`, `upstream_status`, `gg_error_code`, `fault` |
| `mcp_request` / `mcp_request_failed` | Per protocol message except `tools/call` | `mcp_method`, `status`, `elapsed_ms` |
| `mcp_initialize` | Handshake | `client_name`, `client_version`, `protocol_version` |
| `list_tools` | Scope filtering | `tools_exposed`, `tools_hidden`, `hidden_tools` |
| `api_request` | Per outbound GitGuardian API call | `method`, `path` (templated), `status`, `duration_ms`, `gg_request_id` |
| `pagination_complete` | End of a paginated fetch | `items`, `response_bytes`, `truncated`, `pages` |
| `oauth_step` | Each step of the OAuth proxy funnel | `oauth_step`, `outcome`, `status` |

`fault` grades who has to act: `client` for bad input or a missing permission,
`server` for anything worth paging about. Filter on it before reading a failure
list. 408 and 429 count as server fault.

`downstream_ms` includes retry backoff, so `elapsed_ms - downstream_ms` is time
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
# Include extras using the #egg syntax
uvx --from 'git+https://github.com/GitGuardian/ggmcp.git@main#egg=gg-mcp-server[sentry]' gg-mcp-server

# Or install the optional dependency separately
uv pip install sentry-sdk
uvx --from git+https://github.com/GitGuardian/ggmcp.git@main gg-mcp-server
```

### Current Optional Dependencies

- **sentry**: Adds the Sentry SDK for error tracking
  - Core package: `gg-api-core[sentry]`
  - Available in: `gg-mcp-server[sentry]`
  - Implementation: `gg_api_core/src/gg_api_core/sentry_integration.py`
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

Run tests with coverage:

```bash
uv run pytest --cov=packages --cov-report=html
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

## Cursor Rules

This project includes Cursor IDE rules in the `.cursor/rules` directory that enforce coding standards:

1. **Don't use uvicorn or fastapi with MCP** - MCP has its own server implementation, external web servers are not
   needed
2. **Use pyproject.toml with uv** - Modern Python projects should use pyproject.toml with uv for dependency management

These rules help maintain consistent code quality and follow best practices for MCP development.

## Documentation

When adding a new tool, please document it in the README.md following the same structure as existing tools. Include:

1. A brief description of the tool
2. Required environment variables or configuration
3. Tool usage examples
4. Parameter descriptions
5. Response format
6. Integration examples with LLMs
7. Any important notes or warnings

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

## Python 3.13 Features

This project leverages Python 3.13's modern features:

1. **Built-in type annotations**: Use `dict[str, Any]` instead of importing `Dict` from typing
2. **Union types with pipe operator**: Use `str | None` instead of `Optional[str]`
3. **No need for most typing imports**: Many typing constructs are now built into Python

Example:

```python
# Python 3.13 style
def process_data(items: list[str], config: dict[str, Any] | None = None) -> dict[str, Any]:
    # Implementation
    return {"result": True}

# Instead of the older style:
from typing import Dict, List, Optional, Any
def process_data(items: List[str], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    # Implementation
    return {"result": True}
