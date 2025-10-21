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
    mcp.add_tool(tool)
```

## Testing

Run tests using uv:

```bash
uv run pytest
```

Run tests with verbose output:

```bash
uv run pytest -v
```

Run tests with coverage:

```bash
uv run pytest --cov=packages --cov-report=html
```

Create test files in the `tests/` directory that match the pattern `test_*.py`.

## Code Style

This project uses `ruff` for linting and formatting. You can run the linter with:

```bash
ruff check src tests
```

## Cursor Rules

This project includes Cursor IDE rules in the `.cursor/rules` directory that enforce coding standards:

1. **Don't use uvicorn or fastapi with MCP** - MCP has its own server implementation, external web servers are not needed
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

1. Create a new branch for your feature or fix
2. Make your changes, adding tests and documentation
3. Ensure all tests pass and linting issues are fixed
4. Submit a pull request with a clear description of your changes

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