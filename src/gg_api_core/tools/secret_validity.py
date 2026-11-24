"""Tools that read a secret's validity, ask for a new check, and set or remove a validity override."""

import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import uncertain_write_error
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

SECRET_ID_DESCRIPTION = "ID of the secret: an incident's secret_id, not its incident ID"
VALIDITY_VALUES = "valid, invalid, failed_to_check, no_checker or unknown"

_READ_BACK = "Read the secret's validity with get_secret_validity to check"
_CHECK_RAN = (
    "Compare last_checked_at from get_secret_validity with its earlier value to see whether a check ran; "
    "setting an override also moves that date"
)


class SecretValidityParams(BaseModel):
    """Parameters naming one secret."""

    secret_id: NumericId = Field(description=SECRET_ID_DESCRIPTION)


class SetSecretValidityOverrideParams(BaseModel):
    """Parameters for overriding a secret's validity."""

    secret_id: NumericId = Field(description=SECRET_ID_DESCRIPTION)
    validity: Literal["valid", "invalid", "failed_to_check"] = Field(
        description="The validity to record as the override. Must come from the user: ask, do not choose."
    )


class SecretAnalysis(BaseModel):
    """What GitGuardian's analyzer stored about what a secret gives access to."""

    status: str | None = Field(
        description="analyzed (the last analysis succeeded), not_analyzed (no analysis yet, or analysis is "
        "disabled for the workspace), no_analyzer (the detector has none), skipped (the validity was invalid or "
        "failed to check) or failed_to_analyze"
    )
    scopes: list[str] = Field(
        description="Names of the stored active scopes of the secret. They are kept for every status, so they "
        "can come from an earlier successful analysis"
    )
    metadata: dict[str, Any] = Field(
        description="Stored analyzer metadata on what the secret gives access to. Its keys depend on the detector"
    )
    last_analyzed_at: str | None = Field(description="When the last analysis completed or was skipped, if ever")


class SecretValidity(BaseModel):
    """A secret's validity, its validity override and its stored analysis."""

    secret_id: int = Field(description="ID of the secret")
    validity: str | None = Field(
        description=f"The secret's validity now: {VALIDITY_VALUES}. It is the override's value while one is set"
    )
    validity_override: str | None = Field(
        description="The validity override set on the secret, or null when there is none. While it is set, "
        "GitGuardian runs no periodic validity check on the secret, and the secret's incidents follow the override"
    )
    last_checked_at: str | None = Field(
        description="When the secret's validity was last recorded, or null if it never was: by a validity check, "
        "or by setting an override. With no override set, a later date than before a check was requested shows "
        "that the check ran"
    )
    analysis: SecretAnalysis | None = Field(description="Stored analyzer results for the secret")


class ValidityOverrideRemoved(BaseModel):
    """The API's answer to the removal of a validity override."""

    secret_id: int = Field(description="ID of the secret")
    override_removed: bool = Field(
        description="True: the API answered that the override was removed. Periodic validity checks resume, and "
        "a new check recomputes the validity later; this result does not hold that validity"
    )


class ValidityCheckRequested(BaseModel):
    """The API's answer to a validity check request."""

    secret_id: int = Field(description="ID of the secret")
    accepted: bool = Field(
        description="True: the API acknowledged the request. It does not say whether a check was queued, ran or "
        "completed, and the result holds no validity"
    )


def _secret_validity(secret_id: int, response: dict[str, Any]) -> SecretValidity:
    """The tool output for the API's description of a secret's validity."""
    analysis = response.get("analysis")
    return SecretValidity(
        secret_id=secret_id,
        validity=response.get("validity"),
        validity_override=response.get("validity_override"),
        last_checked_at=response.get("last_checked_at"),
        analysis=SecretAnalysis(
            status=analysis.get("status"),
            scopes=[scope["name"] for scope in analysis.get("scopes") or [] if scope.get("name")],
            metadata=analysis.get("metadata") or {},
            last_analyzed_at=analysis.get("last_analyzed_at"),
        )
        if isinstance(analysis, dict)
        else None,
    )


async def get_secret_validity(params: SecretValidityParams) -> SecretValidity:
    """Get a secret's validity, its validity override and its stored analysis."""
    client = await get_client()
    try:
        response = await client.get_secret_validity(params.secret_id)
    except Exception as e:
        raise ToolError(str(e))
    return _secret_validity(params.secret_id, response)


async def set_secret_validity_override(params: SetSecretValidityOverrideParams) -> SecretValidity:
    """Record a validity chosen by the user as a secret's validity override."""
    client = await get_client()
    try:
        response = await client.set_secret_validity_override(params.secret_id, params.validity)
    except Exception as e:
        raise uncertain_write_error(e, _READ_BACK) or ToolError(str(e))
    if "validity_override" not in response:
        raise ToolError(
            "GitGuardian accepted the request without returning the secret's validity, so the override is not "
            f"confirmed. {_READ_BACK}."
        )
    return _secret_validity(params.secret_id, response)


async def remove_secret_validity_override(params: SecretValidityParams) -> ValidityOverrideRemoved:
    """Remove a secret's validity override, so that GitGuardian checks its validity again."""
    client = await get_client()
    try:
        await client.remove_secret_validity_override(params.secret_id)
    except Exception as e:
        raise uncertain_write_error(e, _READ_BACK) or ToolError(str(e))
    return ValidityOverrideRemoved(secret_id=params.secret_id, override_removed=True)


async def request_secret_validity_check(params: SecretValidityParams) -> ValidityCheckRequested:
    """Ask GitGuardian for a new validity check of a secret."""
    client = await get_client()
    try:
        await client.request_secret_validity_check(params.secret_id)
    except Exception as e:
        raise uncertain_write_error(e, _CHECK_RAN) or ToolError(str(e))
    return ValidityCheckRequested(secret_id=params.secret_id, accepted=True)
