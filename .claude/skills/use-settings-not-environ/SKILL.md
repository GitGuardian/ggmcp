---
name: use-settings-not-environ
description: Read env vars through gg_api_core.settings.get_settings(), not os.environ. Triggers when adding a new env-driven config or reviewing code that calls os.environ / os.getenv.
---

# Use `Settings`, not `os.environ`

All env-var access in `gg-mcp` goes through `gg_api_core.settings.Settings`. Adding `os.environ.get(...)` to non-test code is a review-blocker.

## Pattern

```python
# 1. Declare the field on Settings (packages/gg_api_core/src/gg_api_core/settings.py)
github_token: str | None = None   # → reads GITHUB_TOKEN (case-insensitive)

# 2. Read it
from gg_api_core.settings import get_settings
token = get_settings().github_token
```

Derived booleans/lists → add a `@property` on `Settings` (see `is_oauth_enabled`, `requested_scopes`).

## Don't

- `os.environ.get(...)` / `os.getenv(...)` in production code.
- Module-level capture: `_S = get_settings()` — breaks `monkeypatch.setenv` in tests.
- `@lru_cache` on `get_settings` — same reason. It is intentionally uncached.

## OK exceptions

Tests (`monkeypatch.setenv`), pre-`Settings`-import bootstrap, and constructing a subprocess `env=`.
