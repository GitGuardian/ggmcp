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

from tests.conftest import my_vcr


class TestTokenMethods:
    """Tests for token and authentication related methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_current_token_info(self, real_client):
        """
        Test getting current token information.

        GIVEN a valid GitGuardian API key
        WHEN we request the current token info
        THEN we should receive token details including scopes and member_id
        """
        with my_vcr.use_cassette("test_get_current_token_info"):
            result = await real_client.get_current_token_info()

            assert result is not None
            assert "id" in result
            assert "name" in result
            # Token should have scopes (may be "scope" or "scopes" depending on API version)
            assert "scope" in result or "scopes" in result
            # Should have member_id for user context
            assert "member_id" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_api_tokens(self, real_client):
        """
        Test listing all API tokens for the account.

        GIVEN a valid GitGuardian API key with appropriate permissions
        WHEN we request the list of API tokens
        THEN we should receive a list of tokens
        """
        with my_vcr.use_cassette("test_list_api_tokens"):
            result = await real_client.list_api_tokens()

            assert result is not None
            # Result should be a list or contain a list
            if isinstance(result, dict):
                assert "results" in result or "data" in result or isinstance(result.get("tokens"), list)
            else:
                assert isinstance(result, list)


class TestMemberMethods:
    """Tests for member/user related methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_current_member(self, real_client):
        """
        Test getting the current authenticated member's information.

        GIVEN a valid GitGuardian API key
        WHEN we request the current member info
        THEN we should receive member details including email
        """
        with my_vcr.use_cassette("test_get_current_member"):
            result = await real_client.get_current_member()

            assert result is not None
            assert "id" in result
            assert "email" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_members(self, real_client):
        """
        Test listing members in the organization.

        GIVEN a valid GitGuardian API key with member read permissions
        WHEN we request the list of members
        THEN we should receive a list response with member data
        """
        with my_vcr.use_cassette("test_list_members"):
            result = await real_client.list_members(params={"per_page": 5})

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_member_by_id(self, real_client):
        """
        Test getting a specific member by ID.

        GIVEN a valid GitGuardian API key and a valid member ID
        WHEN we request the member info
        THEN we should receive the member's details
        """
        with my_vcr.use_cassette("test_get_member_by_id"):
            # First get the current member to get a valid ID
            current = await real_client.get_current_member()
            member_id = current["id"]

            result = await real_client.get_member(member_id)

            assert result is not None
            assert result["id"] == member_id
            assert "email" in result
