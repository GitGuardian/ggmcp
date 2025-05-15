# Cursor Rules for FastMCP/MCP Development

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

## Code Organization and Imports

1. **Use `src` as the root code directory**
   - Ensure all code is placed within the `src` directory
   - Handle imports accordingly by using the appropriate package path
   - Example: `from src.gitguardian.your_module import YourClass`

2. **FastMCP imports must use the correct package path**
   - All imports concerning FastMCP must be done under `mcp.server.fastmcp`
   - Example: `from mcp.server.fastmcp import FastMCP` instead of direct imports

This guide ensures all MCP implementations follow the project's standards of using native capabilities rather than external web servers.

## Example of correct implementation:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MyServer")

@mcp.tool()
def my_tool():
    return "Hello world"

if __name__ == "__main__":
    # Correct way to run an MCP server - no need for uvicorn
    mcp.run()
```