import logging

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class RevokeSecretParams(BaseModel):
    """Parameters for revoking a secret."""

    secret_id: str | int = Field(description="ID of the secret to revoke")


class RevokeSecretResult(BaseModel):
    """Result from revoking a secret."""

    success: bool = Field(description="Whether the revocation was successful")
    reason: str | None = Field(
        default=None, description="Reason for the revocation result (e.g., error message if failed)"
    )
    is_async: bool | None = Field(default=None, description="Whether the revocation is being processed asynchronously")


async def revoke_secret(params: RevokeSecretParams) -> RevokeSecretResult:
    """
    Revoke a secret by its ID.

    This tool triggers the revocation of a secret through the GitGuardian API.
    The revocation may be processed synchronously or asynchronously depending on
    the secret type and provider.

    Args:
        params: RevokeSecretParams model containing the secret ID to revoke

    Returns:
        RevokeSecretResult: Pydantic model containing:
            - success: Whether the revocation was successful
            - reason: Optional reason for the result (e.g., error message)
            - is_async: Whether the revocation is being processed asynchronously

    Raises:
        ToolError: If the revocation operation fails
    """
    client = await get_client()
    logger.debug(f"Revoking secret with ID: {params.secret_id}")

    try:
        # Make the API call to revoke the secret
        result = await client._request_post(f"/secrets/{params.secret_id}/revoke")

        logger.debug(f"Secret revocation response: {result}")

        # Parse the response into the result model
        if isinstance(result, dict):
            return RevokeSecretResult(
                success=result.get("success", False),
                reason=result.get("reason"),
                is_async=result.get("is_async"),
            )
        else:
            logger.error(f"Unexpected result type: {type(result)}")
            raise ToolError(f"Unexpected response format: {type(result).__name__}")

    except Exception as e:
        logger.exception(f"Error revoking secret {params.secret_id}: {str(e)}")
        raise ToolError(str(e))
