from __future__ import annotations

from typing import Any, Final

SENSITIVE_DATA_PLACEHOLDER: Final = "[REDACTED]"

SENSITIVE_PARAMETER_NAMES: Final = frozenset(
    {
        "key",
        "token",
        "password",
        "secret",
        "authorization",
        "credential",
        "apikey",
        "document",
        "filename",
        "content",
        "match",
        "patch",
        "sensitive",
    }
)

NON_SENSITIVE_NAME_ALLOWLIST: Final = frozenset(
    {
        "secret_id",
        "secret_count",
        "secrets_count",
        "token_id",
        "token_name",
        "match_count",
        "document_count",
        "documents_count",
    }
)

_LEAF_TYPES: Final = (int, float, bool, type(None))


def _name_is_sensitive(name: str) -> bool:
    lowered = name.lower()
    if lowered in NON_SENSITIVE_NAME_ALLOWLIST:
        return False
    return any(token in lowered for token in SENSITIVE_PARAMETER_NAMES)


def scrub_by_name(name: str, value: Any) -> Any:
    if _name_is_sensitive(name):
        return SENSITIVE_DATA_PLACEHOLDER

    if isinstance(value, _LEAF_TYPES) or isinstance(value, str):
        return value

    if isinstance(value, dict):
        return {k: scrub_by_name(str(k), v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        scrubbed = [scrub_by_name(name, item) for item in value]
        try:
            return type(value)(scrubbed)
        except TypeError:
            return scrubbed

    return value
