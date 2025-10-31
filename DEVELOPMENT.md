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

The GitGuardian MCP server supports two authentication modes:

### 1. Local OAuth (stdio transport)
For desktop applications using stdio transport, OAuth authentication is available:

```bash
ENABLE_LOCAL_OAUTH=true developer-mcp-server
```

This will:
- Open a browser for OAuth authentication
- Store the token locally in `~/.gitguardian/`
- Reuse the token across sessions

### 2. Per-Request Authentication (HTTP/SSE transport)
For server deployments using HTTP/SSE transport, use per-request PAT authentication:

```bash
MCP_PORT=8080 MCP_HOST=127.0.0.1 developer-mcp-server
```

Clients must provide authentication via the Authorization header:
```
Authorization: Bearer <your-personal-access-token>
```

**Important:** You cannot use both modes simultaneously. The server will raise an error if both `MCP_PORT` and `ENABLE_LOCAL_OAUTH=true` are set.

### 3. Environment Variable PAT
For all transport modes, you can provide a PAT via environment variable:

```bash
GITGUARDIAN_PERSONAL_ACCESS_TOKEN=<your-pat> developer-mcp-server
```

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
uvx --from 'git+https://github.com/GitGuardian/ggmcp.git@main#egg=secops-mcp-server[sentry]' secops-mcp-server

# Or install the optional dependency separately
uv pip install sentry-sdk
uvx --from git+https://github.com/GitGuardian/ggmcp.git@main secops-mcp-server
```

### Current Optional Dependencies

- **sentry**: Adds Sentry SDK for error tracking and performance monitoring
  - Core package: `gg-api-core[sentry]`
  - Available in: `developer-mcp-server[sentry]`, `secops-mcp-server[sentry]`
  - Implementation: `gg_api_core/src/gg_api_core/sentry_integration.py`
  - Used for: Production error monitoring and alerting
  - See individual package READMEs for configuration details

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

This project uses semantic versioning. To release a new version:

1. Update the version in `pyproject.toml`
2. Update the CHANGELOG.md file
3. Tag the release in git
4. Build and publish the package

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