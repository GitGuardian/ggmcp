"""Identifier types for tool parameters that the client places in an API URL path."""

from typing import Annotated

from pydantic import AfterValidator


def _require_digits(value: str | int) -> str | int:
    # The id is placed in the URL path as given, so text such as "1/../members"
    # would reach another endpoint with the caller's token.
    if isinstance(value, str) and not (value.isascii() and value.isdigit()):
        raise ValueError("must be a numeric ID")
    return value


PathId = Annotated[str | int, AfterValidator(_require_digits)]
