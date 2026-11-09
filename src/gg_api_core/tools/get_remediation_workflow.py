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
    """Retrieve the remediation workflow for the current workspace."""
    client = await get_client()

    try:
        response = await client.get_remediation_workflow()

        return GetRemediationWorkflowResult(workflow=response)
    except Exception as e:
        logger.exception(f"Error retrieving remediation workflow: {str(e)}")
        raise ToolError(str(e))
