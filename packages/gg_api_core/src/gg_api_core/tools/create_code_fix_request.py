import logging

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class LocationToFix(BaseModel):
    """Represents a single issue with locations to fix."""

    issue_id: int = Field(description="The ID of the secret incident")
    location_ids: list[int] = Field(min_length=1, description="List of location IDs to fix for this issue")


class CreateCodeFixRequestParams(BaseModel):
    """Parameters for creating code fix requests."""

    locations: list[LocationToFix] = Field(
        min_length=1,
        description="List of issues with their location IDs to fix. Each item must include an issue_id and a list of location_ids.",
    )


class CreateCodeFixRequestResult(BaseModel):
    """Result from creating code fix requests."""

    model_config = {"extra": "allow"}  # Allow additional fields from API response

    message: str = Field(description="Success message with count of created requests and locations")
    success: bool = Field(default=True, description="Whether the request was successful")


async def create_code_fix_request(params: CreateCodeFixRequestParams) -> CreateCodeFixRequestResult:
    """
    Create code fix requests for multiple secret incidents with their locations.

    This will generate pull requests to automatically remediate the detected secrets.
    Each request must include one or more issues (by issue_id) and one or more
    location IDs for each issue.

    The system will group locations by source repository and create one pull request per source.

    Args:
        params: CreateCodeFixRequestParams model containing:
            - locations: List of issues with their location IDs to fix

    Returns:
        CreateCodeFixRequestResult: Pydantic model containing:
            - message: Success message with count of created requests and locations
            - success: Whether the request was successful
            - Additional fields from the API response

    Raises:
        ToolError: If the request fails due to:
            - 400: Invalid input or business rule violation (e.g., feature disabled,
                   too many locations, no valid locations, already being fixed)
            - 403: Insufficient permissions (not an account admin or missing API scope)
            - 404: API key not configured (on-prem only)

    Examples:
        Single issue with multiple locations:
        ```python
        params = CreateCodeFixRequestParams(
            locations=[LocationToFix(issue_id=12345, location_ids=[67890, 67891, 67892])]
        )
        ```

        Multiple issues from different sources:
        ```python
        params = CreateCodeFixRequestParams(
            locations=[
                LocationToFix(issue_id=12345, location_ids=[67890]),
                LocationToFix(issue_id=12346, location_ids=[67893, 67894]),
            ]
        )
        ```
    """
    client = await get_client()

    # Convert Pydantic models to dict format expected by API
    locations_data = [{"issue_id": loc.issue_id, "location_ids": loc.location_ids} for loc in params.locations]

    total_locations = sum(len(loc.location_ids) for loc in params.locations)
    logger.debug(f"Creating code fix request for {len(params.locations)} issue(s) with {total_locations} location(s)")

    try:
        # Call the client method
        result = await client.create_code_fix_request(locations=locations_data)

        logger.debug("Successfully created code fix request")

        # Parse the response
        if isinstance(result, dict):
            # Extract message before unpacking to avoid duplicate keyword argument
            message = result.get("message", f"Created code fix requests for {len(params.locations)} issue(s)")
            # Remove message from result to avoid duplicate when unpacking
            result_copy = {k: v for k, v in result.items() if k != "message"}
            return CreateCodeFixRequestResult(message=message, success=True, **result_copy)
        else:
            # Fallback response
            return CreateCodeFixRequestResult(
                message=f"Created code fix requests for {len(params.locations)} issue(s)", success=True
            )

    except Exception as e:
        error_message = str(e)
        logger.exception(f"Error creating code fix request: {error_message}")

        # Provide more context based on common error scenarios
        if "not enabled" in error_message.lower():
            raise ToolError("Code fixing feature is not enabled for this workspace")
        elif "permission" in error_message.lower() or "403" in error_message:
            raise ToolError(
                "Insufficient permissions. You must have Manager access level and the 'incidents:write' scope"
            )
        elif "404" in error_message or "not set" in error_message.lower():
            raise ToolError("Code fixing API key is not configured (on-premises only)")
        elif "too many" in error_message.lower():
            raise ToolError("Too many locations in the request. Please reduce the number of locations")
        elif "no valid" in error_message.lower():
            raise ToolError("No valid locations found for the given criteria")
        elif "open pull request" in error_message.lower() or "already" in error_message.lower():
            raise ToolError("Some locations already have open pull requests")
        else:
            raise ToolError(f"Failed to create code fix request: {error_message}")
