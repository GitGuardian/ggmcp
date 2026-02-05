"""
VCR tests for list_repo_occurrences tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesParams,
    ListRepoOccurrencesResult,
    list_repo_occurrences,
)


class TestListRepoOccurrencesVCR:
    """VCR tests for the list_repo_occurrences tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_mine_true(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_repo_occurrences with mine=True
        THEN: The tool returns a valid result (not None) with occurrences
              filtered by the current user's assignments

        This test covers:
        1. The model_validator bug fix : https://github.com/GitGuardian/ggmcp/issues/75
        2. The mine=True filter functionality
        """
        with use_cassette("test_list_repo_occurrences_with_mine_true"):
            # Patch get_client to return the real_client for VCR recording/playback
            with patch(
                "gg_api_core.tools.list_repo_occurrences.get_client",
                return_value=real_client,
            ):
                # Create params with mine=True - this exercises the model_validator
                params = ListRepoOccurrencesParams(
                    mine=True,
                    per_page=10,
                    get_all=False,
                )

                # Verify the model was created correctly (not None)
                # This would fail if model_validator doesn't return self
                assert params is not None
                assert params.mine is True

                # Call the tool
                result = await list_repo_occurrences(params)

                # Verify the result
                assert result is not None
                assert isinstance(result, ListRepoOccurrencesResult)
                assert result.occurrences is not None
                assert isinstance(result.occurrences, list)
                assert result.applied_filters is not None
                assert result.applied_filters.get("mine") is True
