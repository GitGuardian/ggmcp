import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GenerateHoneytokenParams(BaseModel):
    """Parameters for generating a honeytoken."""

    name: str = Field(description="Name for the honeytoken")
    description: str = Field(default="", description="Description of what the honeytoken is used for")
    new_token: bool = Field(
        default=False,
        description="If False, retrieves an existing active honeytoken created by you instead of generating a new one. "
        "If no existing token is found, a new one will be created. "
        "To generate a new token, set this to True.",
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


async def generate_honeytoken(params: GenerateHoneytokenParams) -> GenerateHoneytokenResult:
    """
    Generate an AWS GitGuardian honeytoken and get injection recommendations.

    If new_token is False, attempts to retrieve an existing active honeytoken created by the current user
    instead of generating a new one. If no existing token is found, a new one will be created.

    Args:
        params: GenerateHoneytokenParams model containing honeytoken configuration

    Returns:
        GenerateHoneytokenResult: Pydantic model containing:
            - id: Honeytoken ID
            - name: Honeytoken name
            - description: Honeytoken description
            - type: Honeytoken type
            - status: Honeytoken status
            - token: Token details (if show_token=True was used)
            - injection_recommendations: Instructions for injecting the honeytoken
            - Additional fields from the API response

    Raises:
        ToolError: If the honeytoken generation or retrieval fails
    """
    client = await get_client()
    logger.debug(f"Processing honeytoken request with name: {params.name}, new_token: {params.new_token}")

    # If new_token is False, try to find an existing honeytoken created by the current user
    if not params.new_token:
        try:
            # Get current user's info
            token_info = await client.get_current_token_info()
            if token_info and "user_id" in token_info:
                current_user_id = token_info["user_id"]

                # List honeytokens created by the current user
                filters = {
                    "status": "ACTIVE",  # Only get active tokens
                    "creator_id": current_user_id,
                    "per_page": 10,  # Fetch just a few recent ones
                    "ordering": "-created_at",  # Get newest first
                }

                logger.debug(f"Looking for existing honeytokens for user {current_user_id}")
                result = await client.list_honeytokens(**filters)

                # Process the result to get the list of tokens
                honeytokens = result.get("data", [])

                # Find the most recent active token
                if honeytokens:
                    logger.debug(f"Found {len(honeytokens)} existing honeytokens, using the most recent one")
                    # Get the full honeytoken with token details
                    honeytoken_id = honeytokens[0].get("id")
                    if honeytoken_id:
                        detailed_token = await client.get_honeytoken(honeytoken_id, show_token=True)
                        logger.debug(f"Retrieved existing honeytoken with ID: {honeytoken_id}")
                        return GenerateHoneytokenResult(**detailed_token)

                logger.debug("No suitable existing honeytokens found, creating a new one")
            else:
                logger.warning("Could not determine current user ID, creating a new honeytoken instead")
        except Exception as e:
            logger.warning(f"Error while looking for existing honeytokens: {str(e)}. Creating a new one instead.")

    # Create a new honeytoken if requested or if we couldn't find an existing one
    try:
        # Generate the honeytoken with default tags
        custom_tags = [
            {"key": "source", "value": "auto-generated"},
            {"key": "type", "value": "aws"},
        ]
        creation_result = await client.create_honeytoken(
            name=params.name, description=params.description, custom_tags=custom_tags
        )

        # Validate that we got an ID in the response
        if not creation_result.get("id"):
            raise ToolError("Failed to get honeytoken ID from GitGuardian API")

        logger.debug(f"Generated new honeytoken with ID: {creation_result.get('id')}")

        # Add injection recommendations to the response
        creation_result["injection_recommendations"] = {
            "instructions": "Add the honeytoken to your codebase in configuration files, environment variables, or code comments to detect unauthorized access."
        }

        return GenerateHoneytokenResult(**creation_result)
    except Exception as e:
        logger.exception(f"Error generating honeytoken: {str(e)}")
        raise ToolError(f"Failed to generate honeytoken: {str(e)}")
