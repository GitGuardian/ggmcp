"""
VCR tests for the get_remediation_workflow tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.get_remediation_workflow import (
    GetRemediationWorkflowResult,
    get_remediation_workflow,
)


class TestGetRemediationWorkflowVCR:
    """VCR tests for the get_remediation_workflow tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_remediation_workflow_custom(self, real_client, use_cassette):
        """
        GIVEN: A workspace with a configured custom remediation workflow
        WHEN: Calling get_remediation_workflow
        THEN: Returns the custom workflow with its steps, id and timestamps
        """
        with use_cassette("test_get_remediation_workflow_custom"):
            with patch(
                "gg_api_core.tools.get_remediation_workflow.get_client",
                return_value=real_client,
            ):
                result = await get_remediation_workflow()

                assert result is not None
                assert isinstance(result, GetRemediationWorkflowResult)
                assert isinstance(result.workflow, dict)
                # Configured custom workflow exposes id and timestamps
                assert "id" in result.workflow
                assert "account_id" in result.workflow
                assert "created_at" in result.workflow
                assert "updated_at" in result.workflow
                # Steps are an ordered list with at least a title each
                steps = result.workflow["steps"]
                assert isinstance(steps, list) and len(steps) >= 1
                assert all("title" in step for step in steps)
