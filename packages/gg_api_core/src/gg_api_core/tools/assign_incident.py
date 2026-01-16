import logging
from typing import Any

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

    # Determine the assignee_id based on the provided option
    # Note: Validation that exactly one option is provided is handled by the Pydantic validator
    assignee_id = None

    if params.assignee_member_id is not None:
        # Direct member ID provided
        assignee_id = params.assignee_member_id
        logger.debug(f"Using provided member ID: {assignee_id}")

    elif params.email is not None:
        # Email provided - need to look up member ID
        logger.debug(f"Looking up member ID for email: {params.email}")
        try:
            # Use the /members endpoint to search by email
            result = await client._request_list("/members", params={"search": params.email})
            members = result["data"]

            # Find exact email match
            matching_member: dict[str, Any] | None = None
            for member in members:
                if member.get("email", "").lower() == params.email.lower():
                    matching_member = member
                    break

            if not matching_member:
                raise ToolError(f"No member found with email: {params.email}")

            assignee_id = matching_member.get("id")
            if not assignee_id:
                raise ToolError(f"Member found but no ID available for email: {params.email}")

            logger.debug(f"Found member ID {assignee_id} for email: {params.email}")

        except ToolError:
            raise
        except Exception as e:
            logger.exception(f"Failed to look up member by email: {str(e)}")
            raise ToolError(f"Failed to look up member by email: {str(e)}")

    elif params.mine:
        # Get current user's ID from token info
        token_info = await client.get_current_token_info()
        if token_info and "member_id" in token_info:
            assignee_id = token_info["member_id"]
            logger.debug(f"Using current user ID for assignment: {assignee_id}")
        else:
            raise ToolError("Could not determine current user ID from token info")

    # Final validation
    if not assignee_id:
        raise ToolError("Failed to determine assignee member ID")

    logger.debug(f"Assigning incident {params.incident_id} to member {assignee_id}")

    try:
        # Call the client method
        api_result = await client.assign_incident(incident_id=str(params.incident_id), assignee_id=str(assignee_id))

        logger.debug(f"Successfully assigned incident {params.incident_id} to member {assignee_id}")

        # Parse the response
        if isinstance(api_result, dict):
            # Remove assignee_id from result dict to avoid conflict with our explicit parameter
            result_copy = api_result.copy()
            result_copy.pop("assignee_id", None)
            return AssignIncidentResult(
                incident_id=params.incident_id, assignee_id=assignee_id, success=True, **result_copy
            )
        else:
            # Fallback response
            return AssignIncidentResult(incident_id=params.incident_id, assignee_id=assignee_id, success=True)

    except Exception as e:
        logger.exception(f"Error assigning incident {params.incident_id}: {str(e)}")
        raise ToolError(str(e))
