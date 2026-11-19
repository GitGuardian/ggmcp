# Project structure, technologies and architecture conventions

## Technologies used

- **uv** - dependency and environment management (`pyproject.toml` and `uv.lock`)
- **Python 3.13**
- **FastMCP 4** on the **MCP SDK v2**
- **httpx** (async) for GitGuardian API calls
- **Pydantic** and **pydantic-settings** for tool parameters and configuration
- **Structlog** - structured logging
- **Pytest**, **respx** and **pytest-socket** for tests

## Layout

- `src/gg_api_core/client.py`: the GitGuardian API client. Tools get one from `gg_api_core.utils.get_client()`.
- `src/gg_api_core/tools/`: one module per tool, each with a pydantic params model.
- `src/gg_mcp_server/register_tools.py`: registers every tool with its description and `required_scopes`. The
  scope filter hides the tools a caller's token cannot use.
- `src/gg_mcp_server/http_app.py`: the ASGI app served over HTTP (uvicorn or gunicorn). The `gg-mcp-server`
  command runs over stdio, or over HTTP when `MCP_PORT` is set.
- `src/gg_api_core/settings.py`: read configuration through `get_settings()`, never `os.environ`.

## Conventions

- Import FastMCP from the standalone `fastmcp` package: `from fastmcp import FastMCP`. `mcp.server.fastmcp` does
  not exist in MCP SDK v2.
- A tool's name, input schema, scopes and output are its public contract. Change them deliberately, and pin the API
  request and the tool output in `tests/e2e/`.

# Lower level Python rules

## General Guidelines

- Follow PEP 8 style guidelines
- Add docstrings to all public functions and classes
- Keep imports organized and sorted
- Don't use lazy/deferred imports

## Running tests

Run the tests with `make test`. Lint with `make lint`, type-check with `make typecheck`.

## Creating tests :

- We use pytest, and plain classes. Don't use unittest classes
- Use the existing fixtures instead of building clients by hand: `mock_gitguardian_client` in `tests/conftest.py`,
  and `mcp_client`, `gg_api` and `mock_token_scopes` in `tests/e2e/conftest.py`
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

2. **Describe the tool where clients see it**
    - The tool description is the `description=` passed in `register_tools.py`
    - Parameter descriptions come from the params model fields; the `params` line of the docstring's `Args:` section
      becomes the description of the `params` argument

## Common Mistakes to Avoid

1. **Don't use synchronous functions**
    - Incorrect: `def my_tool():`
    - Correct: `async def my_tool():`

2. **Don't use blocking HTTP libraries**
    - Incorrect: `requests.get(...)`
    - Correct: `async with httpx.AsyncClient() as client: await client.get(...)`
