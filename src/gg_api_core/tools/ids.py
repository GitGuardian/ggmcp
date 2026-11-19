"""Identifier types for tool parameters that the client places in an API URL path."""

from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, Field


def _require_digits(value: str | int) -> str | int:
    # The id is placed in the URL path as given, so text such as "1/../members"
    # would reach another endpoint with the caller's token.
    if isinstance(value, str) and not (value.isascii() and value.isdigit()):
        raise ValueError("must be a numeric ID")
    return value


PathId = Annotated[str | int, AfterValidator(_require_digits)]


def _numeric_id(value: Any) -> Any:
    # Clients send IDs as numbers or as strings of digits. Anything else, such as a
    # boolean or "4_2", which int() would accept, is refused rather than read as an ID.
    if isinstance(value, bool) or (isinstance(value, str) and not (value.isascii() and value.isdigit())):
        raise ValueError("must be a numeric ID")
    return value


# A positive integer ID. A string of digits is accepted and read as that number. The
# bound comes before the validator so the JSON schema states it as a standard minimum.
NumericId = Annotated[int, Field(ge=1), BeforeValidator(_numeric_id)]
