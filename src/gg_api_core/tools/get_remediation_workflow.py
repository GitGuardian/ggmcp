import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GetRemediationWorkflowResult(BaseModel):
    """Result from retrieving the remediation workflow."""

    workflow: dict[str, Any] = Field(description="Remediation workflow data")


async def get_remediation_workflow() -> GetRemediationWorkflowResult:
    """
    Retrieve the remediation workflow for the current workspace.

    This is the ordered, step-by-step remediation guidance shown for secret
    incidents. It returns the workspace's custom remediation workflow when one
    is configured, otherwise a default workflow.

    Returns:
        GetRemediationWorkflowResult: Pydantic model containing:
            - workflow: Remediation workflow dictionary with:
                - account_id: The workspace account identifier
                - steps: Ordered list of remediation steps, each with a
                  ``title`` and optional ``description`` and ``link``
                  (``{"text"?, "url"}``)
                - id, created_at, updated_at: Present only for a configured
                  custom workflow (absent for the default workflow)

    Raises:
        ToolError: If the retrieval operation fails
    """
    client = await get_client()
    logger.debug("Retrieving remediation workflow")

    try:
        response = await client.get_remediation_workflow()

        logger.debug("Retrieved remediation workflow")
        return GetRemediationWorkflowResult(workflow=response)
    except Exception as e:
        logger.exception(f"Error retrieving remediation workflow: {str(e)}")
        raise ToolError(str(e))
