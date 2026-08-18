"""Request identity, downstream timing, and failure fields for logs."""

from __future__ import annotations

import hashlib
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

__all__ = [
    "DownstreamStats",
    "classify_failure",
    "clear_caller_identity_cache",
    "current_downstream_stats",
    "derive_caller_identity",
    "derive_client_identity",
    "record_downstream_call",
    "record_downstream_wait",
    "record_truncation",
    "resolve_caller_identity",
    "scopes_fingerprint",
    "track_downstream_calls",
]

# Logging-only cache; authorization deliberately uses uncached scopes.
_IDENTITY_TTL_SECONDS = 300.0
_IDENTITY_FAILURE_TTL_SECONDS = 30.0
_IDENTITY_CACHE_MAX_ENTRIES = 512

# Stdio has one process identity even when the server does not hold its token.
_NO_TOKEN_KEY = "__no_token__"

# Insertion order supports one-at-a-time eviction.
_identity_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()

logger = logging.getLogger(__name__)


def scopes_fingerprint(scopes: Iterable[str]) -> str:
    """Return an order-independent digest of a scope set."""
    canonical = ",".join(sorted(set(scopes)))
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def derive_caller_identity(token_info: dict[str, Any], *, api_url: str | None = None) -> dict[str, Any]:
    """Map a ``/api_tokens/self`` payload to loggable caller fields."""
    identity: dict[str, Any] = {}

    for source, target in (
        # GitGuardian's API calls the customer identifier `workspace_id`;
        # `account_id` is the shared observability field used by other services.
        ("workspace_id", "account_id"),
        ("workspace_id", "workspace_id"),
        ("member_id", "member_id"),
        ("id", "token_id"),
        ("type", "token_type"),
    ):
        value = token_info.get(source)
        if value is not None:
            identity[target] = value

    scopes = token_info.get("scopes")
    if scopes:
        identity["token_scopes_hash"] = scopes_fingerprint(scopes)

    if api_url:
        host = urlparse(api_url).hostname
        if host:
            identity["gg_host"] = host

    return identity


def _identity_cache_key(token: str | None) -> str:
    """Cache key for a token. The token is hashed, never stored or logged."""
    if token is None:
        return _NO_TOKEN_KEY
    return hashlib.sha256(token.encode()).hexdigest()


def clear_caller_identity_cache(token: str | None = None, *, all_tokens: bool = False) -> None:
    """Drop one token's cached identity, or all entries for tests."""
    if all_tokens:
        _identity_cache.clear()
    else:
        _identity_cache.pop(_identity_cache_key(token), None)


async def resolve_caller_identity(
    fetch_token_info: Callable[[], Awaitable[dict[str, Any]]],
    *,
    token: str | None,
    api_url: str | None = None,
) -> dict[str, Any]:
    """Resolve cached log identity without exposing or storing the raw token."""
    key = _identity_cache_key(token)

    cached = _identity_cache.get(key)
    if cached is not None and cached[0] > time.monotonic():
        return cached[1]

    identity: dict[str, Any]
    try:
        identity = derive_caller_identity(await fetch_token_info(), api_url=api_url)
        ttl = _IDENTITY_TTL_SECONDS
    except Exception as exc:
        logger.debug("caller_identity_unavailable", extra={"reason": str(exc)})
        identity = {}
        ttl = _IDENTITY_FAILURE_TTL_SECONDS

    while len(_identity_cache) >= _IDENTITY_CACHE_MAX_ENTRIES:
        _identity_cache.popitem(last=False)
    _identity_cache[key] = (time.monotonic() + ttl, identity)

    return identity


@dataclass
class DownstreamStats:
    """GitGuardian API statistics for one MCP message."""

    calls: int = 0
    total_ms: float = 0.0
    wait_ms: float = 0.0
    retries: int = 0
    truncated: bool = False
    statuses: set[int] = field(default_factory=set)

    def as_log_fields(self) -> dict[str, Any]:
        """Render counters, including falsey values, as log fields."""
        fields: dict[str, Any] = {
            "downstream_calls": self.calls,
            "downstream_ms": round(self.total_ms),
            "downstream_retries": self.retries,
            "truncated": self.truncated,
        }
        if self.wait_ms:
            fields["downstream_wait_ms"] = round(self.wait_ms)
        if self.statuses:
            fields["downstream_statuses"] = sorted(self.statuses)
        return fields


_downstream_stats: ContextVar[DownstreamStats | None] = ContextVar("gg_downstream_stats", default=None)


@contextmanager
def track_downstream_calls() -> Iterator[DownstreamStats]:
    """Collect downstream API accounting for the duration of the block."""
    stats = DownstreamStats()
    token = _downstream_stats.set(stats)
    try:
        yield stats
    finally:
        _downstream_stats.reset(token)


def current_downstream_stats() -> DownstreamStats | None:
    """The accumulator for the call in flight, if anything is tracking."""
    return _downstream_stats.get()


def record_downstream_call(*, duration_ms: float, status: int | None = None, retried: bool = False) -> None:
    """Add an API call to the active accumulator, if any."""
    stats = _downstream_stats.get()
    if stats is None:
        return
    stats.calls += 1
    stats.total_ms += duration_ms
    if retried:
        stats.retries += 1
    if status is not None:
        stats.statuses.add(status)


def record_downstream_wait(*, duration_ms: float) -> None:
    """Add retry backoff without counting another API call."""
    stats = _downstream_stats.get()
    if stats is not None:
        stats.total_ms += duration_ms
        stats.wait_ms += duration_ms


def record_truncation() -> None:
    """Flag that a response was clipped before reaching the caller."""
    stats = _downstream_stats.get()
    if stats is not None:
        stats.truncated = True


_SERVER_FAULT_CLIENT_CODES = frozenset({408, 429})


def _qualified_name(exc: BaseException) -> str:
    cls = type(exc)
    module = getattr(cls, "__module__", "")
    return cls.__name__ if module in ("builtins", "") else f"{module}.{cls.__name__}"


def _find_status_error(exc: BaseException, _seen: set[int] | None = None) -> httpx.HTTPStatusError | None:
    """Find an HTTP status error through causes and exception groups."""
    seen = _seen if _seen is not None else set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, httpx.HTTPStatusError):
            return current
        seen.add(id(current))

        if isinstance(current, BaseExceptionGroup):
            for nested in current.exceptions:
                found = _find_status_error(nested, seen)
                if found is not None:
                    return found

        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__suppress_context__:
            current = None
        else:
            current = current.__context__
    return None


_GG_ERROR_CODE_MAX_LENGTH = 64


def _gg_error_code(response: httpx.Response) -> str | None:
    """Read a bounded machine error code without logging ``detail`` prose."""
    try:
        body = response.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    for key in ("code", "error"):
        value = body.get(key)
        if isinstance(value, str) and value and len(value) <= _GG_ERROR_CODE_MAX_LENGTH:
            return value
    return None


def classify_failure(exc: BaseException) -> dict[str, Any]:
    """Turn an exception into queryable status and ownership fields."""
    failure: dict[str, Any] = {"error_class": _qualified_name(exc)}

    status_error = _find_status_error(exc)
    if status_error is None:
        # No HTTP status anywhere in the chain: a bug in our code, a timeout, or
        # a validation error raised before the request went out.
        failure["fault"] = "server"
        return failure

    response = status_error.response
    status = response.status_code
    failure["upstream_status"] = status
    failure["fault"] = "client" if 400 <= status < 500 and status not in _SERVER_FAULT_CLIENT_CODES else "server"

    code = _gg_error_code(response)
    if code:
        failure["gg_error_code"] = code

    return failure


def derive_client_identity(client_info: Any, protocol_version: Any = None) -> dict[str, Any]:
    """Map optional MCP initialization metadata to log fields."""
    identity: dict[str, Any] = {}

    name = getattr(client_info, "name", None)
    if name:
        identity["client_name"] = name
    version = getattr(client_info, "version", None)
    if version:
        identity["client_version"] = version
    if protocol_version:
        identity["protocol_version"] = str(protocol_version)

    return identity
