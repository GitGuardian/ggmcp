# Project structure, technologies and architecture conventions

## Technologies used

- **uv** - Fast Python package installer and resolver
- **Python 3.13** - Modern Python with type hints and performance improvements
- **FastMCP** - MCP server implementation
- **Pytest** - Testing framework with fixtures and plugins
- **Pydantic** - Data validation using Python type annotations
- **Structlog** - Structured logging for better observability

## Dependencies Management

1. **Use pyproject.toml with uv**
    - Use `pyproject.toml` for dependency management, not requirements.txt
    - Works well with `uv` for fast, reliable package management
    - Properly specify dependencies with version constraints
    - Use `uv sync` to install dependencies

2. **Example pyproject.toml**
   ```toml
   [build-system]
   requires = ["setuptools>=42", "wheel"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "my-mcp-server"
   version = "0.1.0"
   description = "My MCP server"
   requires-python = ">=3.9"
   dependencies = [
       "mcp>=0.2.0",
       "requests>=2.28.0",
   ]
   ```

## Server Implementation Guidelines

1. **Do NOT use uvicorn or fastapi with MCP/FastMCP**
    - MCP has its own server implementation
    - FastMCP/MCP can run directly using `mcp.run()` with no need for external web servers
    - Avoid adding uvicorn or fastapi to dependencies
    - Do not use `uvicorn.run(...)` in code

2. **Use the correct server method**
    - Use `mcp.run()` to start the server (no additional parameters needed for stdio transport)
    - Example: `mcp.run()` instead of `uvicorn.run(mcp.app, ...)`

3. **Dependencies**
    - Only include required dependencies
    - For basic MCP implementation, only `mcp` or `fastmcp` and possibly `requests` are needed
    - Do not include web server packages unnecessarily

## Code Organization and Imports

1. **Use `src` as the root code directory**
    - Ensure all code is placed within the `src` directory
    - Handle imports accordingly by using the appropriate package path
    - Example: `from src.gitguardian.your_module import YourClass`

2. **FastMCP imports must use the correct package path**
    - All imports concerning FastMCP must be done under `mcp.server.fastmcp`
    - Example: `from mcp.server.fastmcp import FastMCP` instead of direct imports

This guide ensures all MCP implementations follow the project's standards of using native capabilities rather than
external web servers.

# Lower level Python rules

## General Guidelines

- Follow PEP 8 style guidelines
- Add docstrings to all public functions and classes
- Keep imports organized and sorted
- Don't use lazy/deferred imports, except inside Celery tasks definitions

## Running tests

To run the tests, `uv run pytest`

## Creating tests :

- We use pytest, and plain classes. Don't use unittest classes
- Use project fixtures (`test_account`, `owner_client`, `api_client`) instead of creating new instances
- file naming convention : `test_<whatever>.py`
- don't use self.assertEqual (and so on) helpers but only assert
- The docstring of every test function must follow this format :

```
"""
GIVEN ...
WHEN ...
THEN ...
"""
```

## Variable names

Use clear variable and function names that indicate their purpose without being overly verbose.
Follow established conventions where appropriate (e.g., `i` for loop indices, `df` for dataframes),
but ensure non-standard names are self-explanatory.
For example, prefer `calculate_user_discount(price, user_tier)` over `calc(p, t)`, but `i` is perfectly fine for a
simple loop counter.

## **all** Lists

- Add an `__all__` list when using `import *` imports
- When provided, the `__all__ = []` list must be ordered alphabetically
- When adding new items to `__all__`, maintain alphabetical order
- Example:
  ```python
  __all__ = [
      "ClassA",
      "ClassB",
      "function_a",
      "function_b",
  ]
  ```

## Typing

- Use typing for function signatures and return values
- Don't use `from typing import List` but rather `list`

## MCP Tool Definition Guidelines

1. **Methods must be async**
    - All tool methods should be defined as async functions
    - Use `async def` for all tool definitions
    - Use appropriate async libraries and patterns (e.g., httpx.AsyncClient instead of requests)

2. **Include descriptive docstrings**
    - Each tool must have a clear, descriptive docstring
    - Docstrings should explain what the tool does and describe parameters

## Common Mistakes to Avoid

1. **Don't use synchronous functions**
    - Incorrect: `def my_tool():`
    - Correct: `async def my_tool():`

2. **Don't use blocking HTTP libraries**
    - Incorrect: `requests.get(...)`
    - Correct: `async with httpx.AsyncClient() as client: await client.get(...)`
