import logging

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class AssignIncidentParams(BaseModel):
    """Parameters for assigning an incident to a member."""

    incident_id: str | int = Field(description="ID of the secret incident to assign")
    assignee_member_id: str | int | None = Field(
        default=None,
        description="ID of the member to assign the incident to. One of assignee_member_id, email, or mine must be provided",
    )
    email: str | None = Field(
        default=None,
        description="Email address of the member to assign the incident to. One of assignee_member_id, email, or mine must be provided",
    )
    mine: bool = Field(
        default=False,
        description="If True, assign the incident to the current user (will fetch current user's ID automatically). One of assignee_member_id, email, or mine must be provided",
    )

    @model_validator(mode="after")
    def validate_exactly_one_assignee_option(self):
        """Validate that exactly one of assignee_member_id, email, or mine is provided."""
        provided_options = sum([self.assignee_member_id is not None, self.email is not None, self.mine])

        if provided_options == 0:
            raise ValueError("One of assignee_member_id, email, or mine must be provided")
        elif provided_options > 1:
            raise ValueError("Only one of assignee_member_id, email, or mine should be provided")

        return self


class AssignIncidentResult(BaseModel):
    """Result from assigning an incident."""

    model_config = {"extra": "allow"}  # Allow additional fields from API response

    incident_id: str | int = Field(description="ID of the incident that was assigned")
    assignee_id: str | int | None = Field(default=None, description="ID of the member the incident was assigned to")
    success: bool = Field(default=True, description="Whether the assignment was successful")


async def assign_incident(params: AssignIncidentParams) -> AssignIncidentResult:
    """
    Assign a secret incident to a specific member or to the current user.

    This tool assigns a secret incident to a workspace member. You can specify the assignee in three ways:
    - Provide assignee_member_id to assign to a specific member by ID
    - Provide email to assign to a member by their email address
    - Set mine=True to assign to the current authenticated user

    Exactly one of these three options must be provided.

    Args:
        params: AssignIncidentParams model containing:
            - incident_id: ID of the incident to assign
            - assignee_member_id: Optional ID of the member to assign to
            - email: Optional email address of the member to assign to
            - mine: If True, assigns to current user

    Returns:
        AssignIncidentResult: Pydantic model containing:
            - incident_id: ID of the incident that was assigned
            - assignee_id: ID of the member assigned to
            - success: Whether the assignment was successful
            - Additional fields from the API response

    Raises:
        ToolError: If the assignment operation fails
        ValueError: If validation fails (none or multiple assignee options provided)
    """
    client = await get_client()

    # Determine the assignee based on the provided option
    # Note: Validation that exactly one option is provided is handled by the Pydantic validator
    assignee_id = None
    assignee_email = None

    if params.assignee_member_id is not None:
        # Direct member ID provided
        assignee_id = params.assignee_member_id
        logger.debug(f"Using provided member ID: {assignee_id}")

    elif params.email is not None:
        # Email provided - pass directly to API (no need to look up member ID)
        # The API supports assigning by email directly
        assignee_email = params.email
        logger.debug(f"Using provided email for assignment: {assignee_email}")

    elif params.mine:
        # Get current user's ID from token info (avoids needing members:read scope)
        token_info = await client.get_current_token_info()
        if token_info and "member_id" in token_info:
            assignee_id = token_info["member_id"]
            logger.debug(f"Using current user ID for assignment: {assignee_id}")
        else:
            raise ToolError("Could not determine current user ID from token info")

    # Final validation
    if not assignee_id and not assignee_email:
        raise ToolError("Failed to determine assignee (member ID or email)")

    logger.debug(f"Assigning incident {params.incident_id} to member {assignee_id or assignee_email}")

    try:
        # Call the client method with either member_id or email
        api_result = await client.assign_incident(
            incident_id=str(params.incident_id),
            assignee_id=str(assignee_id) if assignee_id else None,
            email=assignee_email,
        )

        logger.debug(f"Successfully assigned incident {params.incident_id} to {assignee_id or assignee_email}")

        # Parse the response - get the actual assignee_id from the API response
        response_assignee_id = assignee_id
        if isinstance(api_result, dict):
            # If we assigned by email, get the member_id from the response
            response_assignee_id = api_result.get("assignee_id") or assignee_id
            # Remove assignee_id from result dict to avoid conflict with our explicit parameter
            result_copy = api_result.copy()
            result_copy.pop("assignee_id", None)
            return AssignIncidentResult(
                incident_id=params.incident_id, assignee_id=response_assignee_id, success=True, **result_copy
            )
        else:
            # Fallback response
            return AssignIncidentResult(incident_id=params.incident_id, assignee_id=response_assignee_id, success=True)

    except Exception as e:
        logger.exception(f"Error assigning incident {params.incident_id}: {str(e)}")
        raise ToolError(str(e))
