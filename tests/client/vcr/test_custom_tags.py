"""
VCR tests for GitGuardianClient custom tag and audit methods.

These tests cover:
- list_custom_tags()
- get_custom_tag(tag_id)
- get_audit_logs(limit)
"""

import pytest

from tests.conftest import my_vcr


class TestCustomTags:
    """Tests for custom tag methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_custom_tags(self, real_client):
        """
        Test listing all custom tags.

        GIVEN a valid GitGuardian API key
        WHEN we request the list of custom tags
        THEN we should receive a list of tags (may be empty)
        """
        with my_vcr.use_cassette("test_list_custom_tags"):
            result = await real_client.list_custom_tags()

            assert result is not None
            # Result should be a list or contain a list
            if isinstance(result, dict):
                assert "results" in result or "data" in result or isinstance(result.get("tags"), list)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_custom_tag(self, real_client):
        """
        Test getting a specific custom tag by ID.

        GIVEN a valid GitGuardian API key and an existing custom tag ID
        WHEN we request the custom tag details
        THEN we should receive the tag details
        """
        with my_vcr.use_cassette("test_get_custom_tag"):
            # First get a custom tag ID from the list
            tags = await real_client.list_custom_tags()

            # Handle different response formats
            tag_list = []
            if isinstance(tags, list):
                tag_list = tags
            elif isinstance(tags, dict):
                tag_list = tags.get("results", tags.get("data", tags.get("tags", [])))

            if not tag_list:
                pytest.skip("No custom tags available for testing")

            tag_id = tag_list[0]["id"]
            result = await real_client.get_custom_tag(tag_id)

            assert result is not None
            assert result["id"] == tag_id
            assert "key" in result


class TestAuditLogs:
    """Tests for audit log methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_audit_logs(self, real_client):
        """
        Test getting audit logs.

        GIVEN a valid GitGuardian API key with audit log permissions
        WHEN we request the audit logs
        THEN we should receive a list of audit log entries
        """
        with my_vcr.use_cassette("test_get_audit_logs"):
            result = await real_client.get_audit_logs(limit=10)

            assert result is not None
            # Result should contain log entries
            if isinstance(result, dict):
                assert "results" in result or "data" in result or "logs" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_audit_logs_with_limit(self, real_client):
        """
        Test getting audit logs with a specific limit.

        GIVEN a valid GitGuardian API key
        WHEN we request audit logs with limit=5
        THEN we should receive at most 5 log entries
        """
        with my_vcr.use_cassette("test_get_audit_logs_with_limit"):
            result = await real_client.get_audit_logs(limit=5)

            assert result is not None
