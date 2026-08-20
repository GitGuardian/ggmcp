"""Shared base model for MCP tool parameter schemas.

Every tool in ``gg_api_core.tools`` accepts a single typed parameter model
(``*Params``). Centralizing their pydantic model config here guarantees a
consistent, security-hardened configuration across all of them.

``hide_input_in_errors=True`` keeps pydantic from embedding the raw tool-call
arguments in ``ValidationError`` messages. When a tool call fails validation
(for example ``scan_secrets`` receiving documents that contain real secrets),
pydantic normally writes the full input dict into the error text as
``input_value={...}``. FastMCP re-raises that text as its own
``ValidationError(str(e))``, and Sentry puts the message verbatim in the event
title. Scrubbing that value after the fact is unreliable, so the sensitive
input is omitted at the source instead.
"""

from pydantic import BaseModel, ConfigDict

__all__ = ["ToolParamsBase"]


class ToolParamsBase(BaseModel):
    """Base class for all MCP tool parameter models.

    ``hide_input_in_errors`` prevents pydantic from echoing the submitted arguments
    into validation errors. Only that setting is centralized here: ``extra`` behavior
    is left at pydantic's default (``ignore``) to preserve each model's existing
    validation semantics.
    """

    model_config = ConfigDict(hide_input_in_errors=True)
