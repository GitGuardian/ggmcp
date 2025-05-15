---
title: "Use pyproject.toml with uv instead of requirements.txt"
description: "Modern Python projects should use pyproject.toml with uv for dependency management"
severity: warning
---

# Use pyproject.toml with uv instead of requirements.txt

## Rule Details

This project uses pyproject.toml for dependency management with uv, not requirements.txt.

### ❌ Incorrect

Using requirements.txt:

```
requests>=2.28.0
mcp>=0.2.0
fastapi>=0.68.0  # Unnecessary
uvicorn>=0.15.0  # Unnecessary
```

Or incorrect installation:

```bash
pip install -r requirements.txt
```

### ✅ Correct

Using pyproject.toml:

```toml
[project]
name = "my-mcp-server"
version = "0.1.0"
description = "My MCP server"
requires-python = ">=3.13"
dependencies = [
    "mcp>=0.2.0",
    "requests>=2.28.0",
]

[dependency-groups]
dev = [
    "pytest>=7.0.0",
    "ruff>=0.0.272",
]
```

With correct installation:

```bash
uv sync
# or with dev dependencies
uv sync --with dev
```

## Add a python package

- Always use `uv add` to add a new python package to the project
- If it's a dev only dependency use `uv add --dev` instead
- You must not directly edit pyproject.toml to add new dependencies

Developer group my by defined as `dependency-groups.dev` in pyproject.toml not `project.optional-dependencies`

### ✅ Correct

[dependency-groups]
dev = [
    "pytest>=8.3.5",
]

### ❌ Incorrect

[project.optional-dependencies]
dev = [
    "pytest>=8.3.5",
]


## Implementation Details

This rule enforces:
- Using pyproject.toml for dependency management
- Using uv for package installation
- Properly specifying dependencies with version constraints
- Not creating or using requirements.txt
- Specifying Python 3.13 as the minimum required version

## Python 3.13 Features

Take advantage of Python 3.13's modern features:
- Use built-in type annotations (`dict[str, Any]` instead of importing `Dict` from typing)
- Use the pipe operator for union types (`str | None` instead of `Optional[str]`)
- Remove unnecessary typing imports as many are now in the standard builtins

## Benefits

- Faster dependency resolution with uv
- Better project metadata with pyproject.toml
- Cleaner separation of development dependencies
- More standardized approach to modern Python packaging
- Ability to leverage the latest Python 3.13 features

## Base directory

- Ensure all code is placed within the `src` directory
- Handle imports accordingly by using the appropriate package path
- Example: `from src.gitguardian.your_module import YourClass`
- the main file is `src/server.py`

## HTTP request client

Use httpx to make all HTTP requests 

## Typing

- use python typing for python > 3.12
- use direct python type instead of importing from typing. 

### ❌ Incorrect
from typing import Dict, List

def my_func(my_dict: Dict, my_list: List):
    ...


### ✅ Correct

def my_func(my_dict: dict, my_list: list):
    ...
