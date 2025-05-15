---
title: "Don't use uvicorn or fastapi with MCP"
description: "MCP has native server capabilities, external web servers are not needed"
severity: warning
---

# Don't use uvicorn or fastapi with MCP/FastMCP

## Rule Details

MCP and FastMCP have their own server implementations that can run directly without external web servers like uvicorn or fastapi.

### ❌ Incorrect

```python
# Incorrect: Using uvicorn with MCP
import uvicorn
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MyServer")

if __name__ == "__main__":
    uvicorn.run(mcp.app, host="0.0.0.0", port=8000)  # Wrong
```

### ✅ Correct

```python
# Correct: Using MCP's native run method
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MyServer")

if __name__ == "__main__":
    mcp.run()  # Correct
```

## Implementation Details

This rule enforces:
- Not using uvicorn or fastapi with MCP servers
- Using the native `mcp.run()` method instead
- Not adding unnecessary web server dependencies

## Dependencies

When working with MCP and Python 3.13, avoid unnecessary dependencies:
- For basic MCP implementation, only `mcp` or `fastmcp` and possibly `requests` are needed
- Do not include web server packages unnecessarily
- Take advantage of Python 3.13's built-in typing features (using `list[str]` instead of `List[str]`)

## Configuration in pyproject.toml

```toml
[project]
requires-python = ">=3.13"
dependencies = [
    "mcp>=0.2.0",
    "requests>=2.28.0",
    # No uvicorn or fastapi
]
```

## Import fastmcp from mcp

**FastMCP imports must use the correct package path**
- All imports concerning FastMCP must be done under `mcp.server.fastmcp`
- Example: `from mcp.server.fastmcp import FastMCP` instead of direct imports
