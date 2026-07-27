from __future__ import annotations

import re
from datetime import date, datetime
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

_LEAF_TYPES: Final = (int, float, bool, date, datetime, type(None))

_SENSITIVE_URL_PARAMS_RE = re.compile(rf"(({'|'.join(SENSITIVE_PARAMETER_NAMES)})=)([^&]+)(&|$)")
_SENSITIVE_GIT_CLONE_RE = re.compile(r"(https?://)[^:@/\s]*:[^@/\s]*@")


def scrub_url_params(string: str) -> str:
    return _SENSITIVE_URL_PARAMS_RE.sub(rf"\1{SENSITIVE_DATA_PLACEHOLDER}\4", string)


def scrub_git_credentials(string: str) -> str:
    return _SENSITIVE_GIT_CLONE_RE.sub(
        rf"\1{SENSITIVE_DATA_PLACEHOLDER}:{SENSITIVE_DATA_PLACEHOLDER}@",
        string,
    )


def scrub_by_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    value = scrub_url_params(value)
    value = scrub_git_credentials(value)
    return value


def _name_is_sensitive(name: str) -> bool:
    lowered = name.lower()
    if lowered in NON_SENSITIVE_NAME_ALLOWLIST:
        return False
    return any(token in lowered for token in SENSITIVE_PARAMETER_NAMES)


def scrub_by_name(name: str, value: Any) -> Any:
    if _name_is_sensitive(name):
        return SENSITIVE_DATA_PLACEHOLDER

    if isinstance(value, dict):
        return {k: scrub_by_name(str(k), v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        scrubbed = [scrub_by_name(name, item) for item in value]
        try:
            return type(value)(scrubbed)
        except TypeError:
            return scrubbed

    if isinstance(value, str):
        return scrub_by_value(value)

    if isinstance(value, _LEAF_TYPES):
        return value

    return value
