import logging
from typing import Any

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import api_error_detail
from gg_api_core.tools.incident_writes import uncertain_write_error
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GenerateHoneytokenParams(BaseModel):
    """Parameters for generating a honeytoken."""

    name: str = Field(
        description="Name for the honeytoken. Must be UNIQUE among the workspace's active honeytokens — "
        "reusing the name of an existing active token is rejected by the API. Pick a specific, descriptive "
        "name (e.g. 'aws-prod-db-decoy-2026-07'), not a generic one."
    )
    description: str = Field(default="", description="Description of what the honeytoken is used for")
    new_token: bool = Field(
        default=False,
        description="If False (default), reuse your most recent active honeytoken instead of generating a new one; "
        "the name is only used when no reusable token exists and one must be created. "
        "If True, always create a new honeytoken — this fails if the name is already taken, so pass a fresh unique name.",
    )


class GenerateHoneytokenResult(BaseModel):
    """Result from generating or retrieving a honeytoken."""

    model_config = {"extra": "allow"}  # Allow additional fields from API

    id: str | int = Field(description="Honeytoken ID")
    name: str | None = Field(default=None, description="Honeytoken name")
    description: str | None = Field(default=None, description="Honeytoken description")
    type: str | None = Field(default=None, description="Honeytoken type")
    status: str | None = Field(default=None, description="Honeytoken status")
    token: dict[str, Any] | None = Field(default=None, description="Token details if show_token=True")
    injection_recommendations: dict[str, Any] | None = Field(default=None, description="Injection recommendations")
    reused: bool = Field(
        description="True when this is your most recent active honeytoken, returned instead of creating one; False "
        "when this call created it"
    )


# How to see whether a creation whose outcome is unknown went through: without new_token,
# the tool returns the caller's most recent active honeytoken.
_CREATION_CHECK = (
    "Creating another may leave two: call generate_honeytoken without new_token, which returns your most recent "
    "active honeytoken, to check"
)

# Returned with every honeytoken, reused or created.
INJECTION_RECOMMENDATIONS = {
    "instructions": "Add the honeytoken to your codebase in configuration files, environment variables, "
    "or code comments to detect unauthorized access."
}


async def _most_recent_active_honeytoken(client: Any) -> dict[str, Any] | None:
    """Return the caller's most recent active honeytoken, or None when they have none.

    Any failure raises instead of returning None: a request to reuse a token
    that cannot check for an existing one must not go on to create a new live
    honeytoken.
    """
    try:
        token_info = await client.get_current_token_info()
        member_id = (token_info or {}).get("member_id")
        if member_id is None:
            raise ToolError(
                "No honeytoken was created: this token is not tied to a workspace member, so there is no way "
                "to find your existing honeytokens. Pass new_token=true to create a new one."
            )
        result = await client.list_honeytokens(
            # The API only accepts the lowercase status values.
            status="active",
            creator_id=member_id,
            per_page=10,
            ordering="-created_at",
        )
        honeytokens = result.get("data", [])
        if not honeytokens or not honeytokens[0].get("id"):
            return None
        return await client.get_honeytoken(honeytokens[0]["id"], show_token=True)
    except ToolError:
        raise
    except httpx.HTTPStatusError as e:
        detail = api_error_detail(e.response)
        logger.warning(f"Honeytoken reuse lookup failed ({e.response.status_code}): {detail}")
        raise ToolError(
            f"No honeytoken was created: looking up your existing honeytokens failed ({detail}). "
            "Pass new_token=true to create a new one anyway."
        ) from e
    except Exception as e:
        raise ToolError(
            f"No honeytoken was created: looking up your existing honeytokens failed ({e}). "
            "Pass new_token=true to create a new one anyway."
        ) from e


async def generate_honeytoken(params: GenerateHoneytokenParams) -> GenerateHoneytokenResult:
    """Generate an AWS GitGuardian honeytoken and get injection recommendations.

    Args:
        params: GenerateHoneytokenParams model containing honeytoken configuration
    """
    client = await get_client()

    # Reuse the caller's most recent active honeytoken unless a new one was asked for.
    # Creation only follows a lookup that succeeded and found nothing to reuse.
    if not params.new_token:
        existing = await _most_recent_active_honeytoken(client)
        if existing is not None:
            return GenerateHoneytokenResult.model_validate(
                {**existing, "injection_recommendations": INJECTION_RECOMMENDATIONS, "reused": True}
            )

    # Create a new honeytoken: requested, or the caller has none to reuse
    try:
        # Generate the honeytoken with default tags
        custom_tags: list[dict[str, str | None]] = [
            {"key": "source", "value": "auto-generated"},
            {"key": "type", "value": "aws"},
        ]
        creation_result = await client.create_honeytoken(
            name=params.name, description=params.description, custom_tags=custom_tags
        )

        # Validate that we got an ID in the response
        if not creation_result.get("id"):
            raise ToolError("Failed to get honeytoken ID from GitGuardian API")

        return GenerateHoneytokenResult.model_validate(
            {**creation_result, "injection_recommendations": INJECTION_RECOMMENDATIONS, "reused": False}
        )
    except ToolError:
        raise
    except httpx.HTTPStatusError as e:
        if uncertain := uncertain_write_error(e, _CREATION_CHECK):
            raise uncertain from e
        # The API rejected the request — most often because an active honeytoken with
        # this name already exists (names are unique per workspace). This is an expected,
        # caller-actionable condition, not a server fault: surface the API's reason so the
        # client can retry with a different name (or adjust new_token). Log at warning so
        # it does not surface as a Sentry error.
        detail = api_error_detail(e.response)
        logger.warning(f"Honeytoken creation rejected ({e.response.status_code}): {detail}")
        raise ToolError(f"Could not create honeytoken: {detail}") from e
    except Exception as e:
        raise uncertain_write_error(e, _CREATION_CHECK) or ToolError(f"Failed to generate honeytoken: {str(e)}")
