import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class AssignPublicIncidentParams(BaseModel):
    """Parameters for assigning a public secret incident to a member."""

    incident_id: int = Field(description="ID of the public secret incident to assign")
    assignee_member_id: int | None = Field(
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
    send_email: bool | None = Field(
        default=None,
        description="If False, skip notifying the assignee. Defaults to the API default (True) when omitted.",
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


class AssignPublicIncidentResult(BaseModel):
    """Result from assigning a public secret incident."""

    model_config = {"extra": "allow"}

    incident_id: int = Field(description="ID of the public incident that was assigned")
    assignee_id: int | None = Field(default=None, description="ID of the member the incident was assigned to")
    success: bool = Field(default=True, description="Whether the assignment was successful")
    incident: dict[str, Any] | None = Field(default=None, description="Full updated public incident payload")


async def assign_public_incident(params: AssignPublicIncidentParams) -> AssignPublicIncidentResult:
    """
    Assign a public secret incident to a specific member or to the current user.

    Public incidents are surfaced by GitGuardian Public Monitoring (public GitHub repos/gists,
    Docker Hub, etc.). Public incident IDs are NOT interchangeable with internal incident IDs;
    use this tool — not `assign_incident` — when acting on results from `list_public_incidents`
    or `get_public_incident`.

    You can specify the assignee in three ways:
    - Provide assignee_member_id to assign to a specific member by ID
    - Provide email to assign to a member by their email address
    - Set mine=True to assign to the current authenticated user

    Exactly one of these three options must be provided.

    Wraps POST /v1/public-incidents/secrets/{incident_id}/assign.

    Args:
        params: AssignPublicIncidentParams model containing:
            - incident_id: ID of the public incident to assign
            - assignee_member_id: Optional ID of the member to assign to
            - email: Optional email address of the member to assign to
            - mine: If True, assigns to current user
            - send_email: If False, skip notifying the assignee

    Returns:
        AssignPublicIncidentResult: Pydantic model containing:
            - incident_id: ID of the public incident that was assigned
            - assignee_id: ID of the member assigned to (resolved from API response if assigning by email)
            - success: Whether the assignment was successful
            - incident: Full updated public incident payload from the API

    Raises:
        ToolError: If the assignment operation fails
        ValueError: If validation fails (none or multiple assignee options provided)
    """
    client = await get_client()

    assignee_id: int | None = None
    assignee_email: str | None = None

    if params.assignee_member_id is not None:
        assignee_id = params.assignee_member_id
        logger.debug(f"Using provided member ID: {assignee_id}")

    elif params.email is not None:
        assignee_email = params.email
        logger.debug(f"Using provided email for assignment: {assignee_email}")

    elif params.mine:
        token_info = await client.get_current_token_info()
        if token_info and "member_id" in token_info:
            assignee_id = int(token_info["member_id"])
            logger.debug(f"Using current user ID for assignment: {assignee_id}")
        else:
            raise ToolError("Could not determine current user ID from token info")

    if assignee_id is None and assignee_email is None:
        raise ToolError("Failed to determine assignee (member ID or email)")

    logger.debug(f"Assigning public incident {params.incident_id} to member {assignee_id or assignee_email}")

    try:
        api_result = await client.assign_public_incident(
            incident_id=params.incident_id,
            assignee_id=assignee_id,
            email=assignee_email,
            send_email=params.send_email,
        )

        logger.debug(f"Successfully assigned public incident {params.incident_id} to {assignee_id or assignee_email}")

        response_assignee_id = assignee_id
        if isinstance(api_result, dict):
            api_assignee_id = api_result.get("assignee_id")
            if api_assignee_id is not None:
                response_assignee_id = api_assignee_id
            return AssignPublicIncidentResult(
                incident_id=params.incident_id,
                assignee_id=response_assignee_id,
                success=True,
                incident=api_result,
            )

        return AssignPublicIncidentResult(
            incident_id=params.incident_id,
            assignee_id=response_assignee_id,
            success=True,
        )

    except Exception as e:
        logger.exception(f"Error assigning public incident {params.incident_id}: {str(e)}")
        raise ToolError(str(e))
