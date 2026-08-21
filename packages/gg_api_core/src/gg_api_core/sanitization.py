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
        # Describes a token rather than carrying one: "personal_access_token"
        # or "service_account", and a digest of the scope set.
        "token_type",
        "token_scopes_hash",
        "match_count",
        "document_count",
        "documents_count",
    }
)

_LEAF_TYPES: Final = (int, float, bool, date, datetime, type(None))

_SENSITIVE_URL_PARAMS_RE = re.compile(rf"(({'|'.join(SENSITIVE_PARAMETER_NAMES)})=)([^&]+)(&|$)")
_SENSITIVE_GIT_CLONE_RE = re.compile(r"(https?://)[^:@/\s]*:[^@/\s]*@")

# Pydantic renders the rejected input into every ValidationError message as
# ``input_value=<repr>, input_type=<type>]``. FastMCP validates tool calls
# against a TypeAdapter built from the tool signature rather than against the
# ``*Params`` model, so ``hide_input_in_errors`` on the model does not reach
# this text and the raw arguments travel with the exception message.
_PYDANTIC_INPUT_VALUE_RE = re.compile(r"input_value=[^\n]*")


def scrub_url_params(string: str) -> str:
    return _SENSITIVE_URL_PARAMS_RE.sub(rf"\1{SENSITIVE_DATA_PLACEHOLDER}\4", string)


def scrub_git_credentials(string: str) -> str:
    return _SENSITIVE_GIT_CLONE_RE.sub(
        rf"\1{SENSITIVE_DATA_PLACEHOLDER}:{SENSITIVE_DATA_PLACEHOLDER}@",
        string,
    )


def _redact_input_value(match: re.Match[str]) -> str:
    """Replace one ``input_value=`` payload, keeping the diagnostic tail.

    Pydantic always renders ``input_type`` after ``input_value``, so the tail
    starts at the last such marker on the line. Taking the last one keeps a
    payload that embeds the marker itself fully redacted.
    """
    rest = match.group(0)
    marker = rest.rfind(", input_type=")
    return f"input_value={SENSITIVE_DATA_PLACEHOLDER}{rest[marker:] if marker != -1 else ''}"


def scrub_pydantic_input_value(string: str) -> str:
    """Redact the rejected input embedded in pydantic validation messages.

    ``input_type`` and the error type are kept: they describe the failure
    without carrying the submitted data.
    """
    return _PYDANTIC_INPUT_VALUE_RE.sub(_redact_input_value, string)


def scrub_by_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    value = scrub_url_params(value)
    value = scrub_git_credentials(value)
    value = scrub_pydantic_input_value(value)
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


def scrub_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    """Return a new mapping with each value redacted under its key name.

    Each key is treated as the sensitivity signal for its value: a value is
    replaced with the placeholder when its key name matches a sensitive
    parameter, and nested mapping/list values are scrubbed recursively.

    Args:
        mapping: The mapping to scrub.

    Returns:
        A new mapping with sensitive values redacted.
    """
    return {key: scrub_by_name(str(key), value) for key, value in mapping.items()}
