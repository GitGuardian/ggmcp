"""
VCR tests for read_custom_tags tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.read_custom_tags import (
    ReadCustomTagsParams,
    read_custom_tags,
)


class TestReadCustomTagsVCR:
    """VCR tests for the read_custom_tags tool.

    These tests cover the two actions supported by the tool:
    - list_tags: List all custom tags in the workspace
    - get_tag: Get a specific custom tag by ID
    """

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_read_custom_tags_list_all(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with custom_tags:read scope
        WHEN: Calling read_custom_tags with action='list_tags'
        THEN: Returns a list of all custom tags in the workspace

        Uses cassette: test_list_custom_tags.yaml (existing)
        """
        with use_cassette("test_list_custom_tags"):
            with patch(
                "gg_api_core.tools.read_custom_tags.get_client",
                return_value=real_client,
            ):
                params = ReadCustomTagsParams(
                    action="list_tags",
                    tag_id="unused",  # Required by model but ignored for list_tags
                )

                result = await read_custom_tags(params)

                assert result is not None
                assert isinstance(result, list)
                # Verify tag structure if tags exist
                if result:
                    tag = result[0]
                    assert "id" in tag
                    assert "key" in tag
                    # value can be None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_read_custom_tags_get_single_tag(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with custom_tags:read scope
        WHEN: Calling read_custom_tags with action='get_tag' and a valid tag_id
        THEN: Returns the specific custom tag details

        Uses cassette: test_get_custom_tag.yaml (existing)
        Note: The cassette contains both a list call and a get call.
        """
        # Use a tag ID that exists in the cassette data
        tag_id = "9df8c1c9-7367-4c77-a0f0-9f2d4b22bdda"

        with use_cassette("test_get_custom_tag"):
            with patch(
                "gg_api_core.tools.read_custom_tags.get_client",
                return_value=real_client,
            ):
                params = ReadCustomTagsParams(
                    action="get_tag",
                    tag_id=tag_id,
                )

                result = await read_custom_tags(params)

                assert result is not None
                assert isinstance(result, dict)
                assert "id" in result
                assert "key" in result
                assert result["id"] == tag_id
                assert result["key"] == "commiter"
                assert result["value"] == "leaky mcgee"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_read_custom_tags_get_tag_verifies_structure(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with custom_tags:read scope
        WHEN: Calling read_custom_tags with action='get_tag'
        THEN: The returned tag has the expected structure with id, key, value

        Uses cassette: test_get_custom_tag.yaml (existing)
        This tests that tag data structure is correct.
        """
        # Use a tag ID that exists in the cassette data
        tag_id = "9df8c1c9-7367-4c77-a0f0-9f2d4b22bdda"

        with use_cassette("test_get_custom_tag"):
            with patch(
                "gg_api_core.tools.read_custom_tags.get_client",
                return_value=real_client,
            ):
                params = ReadCustomTagsParams(
                    action="get_tag",
                    tag_id=tag_id,
                )

                result = await read_custom_tags(params)

                # Verify full structure
                assert result is not None
                assert isinstance(result, dict)
                assert set(result.keys()) == {"id", "key", "value"}
                assert isinstance(result["id"], str)
                assert isinstance(result["key"], str)
                # value can be string or None
