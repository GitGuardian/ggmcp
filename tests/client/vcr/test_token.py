"""
VCR tests for GitGuardianClient token and authentication methods.

These tests cover:
- get_current_token_info()
- list_api_tokens()
- get_current_member()
- get_member(member_id)
- list_members(params)
"""

import pytest


class TestMemberMethods:
    """Tests for member/user related methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_member_by_id(self, real_client, use_cassette):
        """
        Test getting a specific member by ID.

        GIVEN a valid GitGuardian API key and a valid member ID
        WHEN we request the member info
        THEN we should receive the member's details
        """
        with use_cassette("test_get_member_by_id"):
            # First get the current member to get a valid ID
            current = await real_client.get_current_member()
            member_id = current["id"]

            result = await real_client.get_member(member_id)

            assert result is not None
            assert result["id"] == member_id
            assert "email" in result
