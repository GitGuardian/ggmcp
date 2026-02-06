"""
VCR tests for get_member tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.get_member import (
    GetMemberParams,
    GetMemberResult,
    get_member,
)


class TestGetMemberVCR:
    """VCR tests for the get_member tool."""

    # Member ID from the list_members cassette (Aymeric Sicard - manager)
    TEST_MEMBER_ID = 13

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_member_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling get_member with a member ID
        THEN: Returns the member details
        """
        with use_cassette("test_get_member_basic"):
            with patch(
                "gg_api_core.tools.get_member.get_client",
                return_value=real_client,
            ):
                params = GetMemberParams(
                    member_id=self.TEST_MEMBER_ID,
                )

                result = await get_member(params)

                assert result is not None
                assert isinstance(result, GetMemberResult)
                assert result.member is not None
                assert isinstance(result.member, dict)
                # Verify basic member structure
                assert "id" in result.member
                assert "email" in result.member
                assert "name" in result.member
                assert "role" in result.member
                assert "access_level" in result.member
                assert "active" in result.member

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_member_has_timestamps(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling get_member with a member ID
        THEN: Returns the member with timestamp fields
        """
        with use_cassette("test_get_member_has_timestamps"):
            with patch(
                "gg_api_core.tools.get_member.get_client",
                return_value=real_client,
            ):
                params = GetMemberParams(
                    member_id=self.TEST_MEMBER_ID,
                )

                result = await get_member(params)

                assert result is not None
                assert result.member is not None
                # Verify timestamp fields are present
                assert "created_at" in result.member
                assert "last_login" in result.member

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_member_verifies_id(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling get_member with a specific member ID
        THEN: Returns the member with the matching ID
        """
        with use_cassette("test_get_member_verifies_id"):
            with patch(
                "gg_api_core.tools.get_member.get_client",
                return_value=real_client,
            ):
                params = GetMemberParams(
                    member_id=self.TEST_MEMBER_ID,
                )

                result = await get_member(params)

                assert result is not None
                assert result.member is not None
                # Verify the returned member ID matches the requested ID
                assert result.member["id"] == self.TEST_MEMBER_ID
