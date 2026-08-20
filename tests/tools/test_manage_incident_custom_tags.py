from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.manage_incident_custom_tags import (
    IncidentCustomTagsParams,
    _resolve_tags,
    manage_incident_custom_tags,
)
from pydantic import ValidationError


class TestIncidentCustomTagsParams:
    """
    Test IncidentCustomTagsParams validation.
    """

    def test_action_defaults_to_add(self):
        """
        GIVEN an incident_id and tags without an action
        WHEN creating IncidentCustomTagsParams
        THEN the action defaults to "add"
        """
        params = IncidentCustomTagsParams(incident_id="123", custom_tags=["env"])
        assert params.action == "add"

    def test_incident_with_single_tag_key_only(self):
        """
        GIVEN an incident_id and tag with key only
        WHEN creating IncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = IncidentCustomTagsParams(incident_id="123", custom_tags=["env"])
        assert params.incident_id == 123
        assert params.custom_tags == ["env"]

    def test_incident_with_single_tag_key_value(self):
        """
        GIVEN an incident_id and tag with key:value format
        WHEN creating IncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = IncidentCustomTagsParams(incident_id="123", custom_tags=["env:prod"])
        assert params.incident_id == 123
        assert params.custom_tags == ["env:prod"]

    def test_incident_with_multiple_tags(self):
        """
        GIVEN an incident_id and multiple tags
        WHEN creating IncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = IncidentCustomTagsParams(incident_id="123", custom_tags=["env", "env:prod", "region:us-west-2"])
        assert params.incident_id == 123
        assert len(params.custom_tags) == 3
        assert "env" in params.custom_tags
        assert "env:prod" in params.custom_tags
        assert "region:us-west-2" in params.custom_tags

    def test_incident_id_as_int(self):
        """
        GIVEN an incident_id as integer
        WHEN creating IncidentCustomTagsParams
        THEN it should be accepted
        """
        params = IncidentCustomTagsParams(incident_id=123, custom_tags=["env:prod"])
        assert params.incident_id == 123

    def test_incident_id_as_string(self):
        """
        GIVEN an incident_id as numeric string
        WHEN creating IncidentCustomTagsParams
        THEN it is coerced to int
        """
        params = IncidentCustomTagsParams(incident_id="123", custom_tags=["env:prod"])
        assert params.incident_id == 123

    def test_empty_key_is_rejected_at_model_boundary(self):
        """
        GIVEN a custom tag with a whitespace-only key
        WHEN creating IncidentCustomTagsParams
        THEN a ValidationError is raised and no client is involved
        """
        with pytest.raises(ValidationError, match="key cannot be empty"):
            IncidentCustomTagsParams(incident_id=123, custom_tags=[" : x"])


class TestResolveTags:
    """
    Test the pure _resolve_tags helper.
    """

    def test_add_merges_preserving_order_and_deduplicating(self):
        """
        GIVEN current and requested overlapping tag sets
        WHEN resolving with action "add"
        THEN the result is the union: existing order first, new tags appended, no duplicates
        """
        current = [("team", "red"), ("env", "prod")]
        requested = [("env", "prod"), ("status", "reviewed")]
        assert _resolve_tags("add", current, requested) == [
            ("team", "red"),
            ("env", "prod"),
            ("status", "reviewed"),
        ]

    def test_remove_drops_only_the_requested_tags(self):
        """
        GIVEN current tags including some requested for removal
        WHEN resolving with action "remove"
        THEN only the requested tags are dropped, remaining order is kept
        """
        current = [("team", "red"), ("env", "prod"), ("status", "reviewed")]
        assert _resolve_tags("remove", current, [("env", "prod")]) == [
            ("team", "red"),
            ("status", "reviewed"),
        ]

    def test_remove_of_absent_tag_is_a_no_op(self):
        """
        GIVEN a requested tag not present in current
        WHEN resolving with action "remove"
        THEN the result is unchanged
        """
        current = [("team", "red")]
        assert _resolve_tags("remove", current, [("env", "prod")]) == [("team", "red")]

    def test_remove_matches_full_key_value_pair_not_bare_key(self):
        """
        GIVEN a current tag stored with a value
        WHEN removing it by bare key with no value
        THEN it does not match (dedup is on the full (key, value) pair); the tag
             is kept, so a bare-key remove is a silent no-op
        """
        current = [("env", "prod")]
        # request by bare key (value None) vs stored env:prod -> no match
        assert _resolve_tags("remove", current, [("env", None)]) == [("env", "prod")]
        # matching by the exact key:value pair does remove it
        assert _resolve_tags("remove", current, [("env", "prod")]) == []

    def test_set_replaces_the_whole_set(self):
        """
        GIVEN current and requested tag sets
        WHEN resolving with action "set"
        THEN the result is just the requested set, deduplicated
        """
        current = [("team", "red"), ("env", "prod")]
        requested = [("status", "reviewed"), ("status", "reviewed")]
        assert _resolve_tags("set", current, requested) == [("status", "reviewed")]

    def test_set_deduplicates_requested(self):
        """
        GIVEN a requested set with duplicate entries
        WHEN resolving with action "set"
        THEN duplicates are collapsed
        """
        requested = [("env", "prod"), ("env", "prod"), ("env", "staging")]
        assert _resolve_tags("set", [], requested) == [("env", "prod"), ("env", "staging")]


class TestManageIncidentCustomTags:
    """
    Test manage_incident_custom_tags against a mocked client.
    """

    @staticmethod
    def _client(existing_tags):
        mock_client = AsyncMock()
        mock_client.get_incident.return_value = {"id": 123, "custom_tags": existing_tags}
        mock_client.update_incident.return_value = {"id": 123}
        return mock_client

    @pytest.mark.asyncio
    async def test_add_preserves_existing_tags(self):
        """
        GIVEN an incident that already carries tags
        WHEN adding a new tag
        THEN the PATCH payload is the union: existing tags first, then the new one
        """
        mock_client = self._client(
            [
                {"id": "t1", "key": "team", "value": "red"},
                {"id": "t2", "key": "env", "value": "prod"},
            ]
        )

        params = IncidentCustomTagsParams(incident_id=123, custom_tags=["status:reviewed"])
        with patch("gg_api_core.tools.manage_incident_custom_tags.get_client", return_value=mock_client):
            result = await manage_incident_custom_tags(params)

        assert result == {"id": 123}
        mock_client.get_incident.assert_awaited_once_with(123, with_occurrences=0)
        mock_client.update_incident.assert_awaited_once_with(
            incident_id="123",
            custom_tags=[
                {"key": "team", "value": "red"},
                {"key": "env", "value": "prod"},
                {"key": "status", "value": "reviewed"},
            ],
        )

    @pytest.mark.asyncio
    async def test_tags_are_normalized_like_the_api(self):
        """
        GIVEN tags with surrounding whitespace, an empty value, and a value containing colons
        WHEN updating an incident with no existing tags
        THEN keys/values are stripped, empty values become None, and only the first colon splits
        """
        mock_client = self._client([])

        params = IncidentCustomTagsParams(
            incident_id=123, custom_tags=[" env : prod ", "reviewed:", "url:http://example.com"]
        )
        with patch("gg_api_core.tools.manage_incident_custom_tags.get_client", return_value=mock_client):
            await manage_incident_custom_tags(params)

        mock_client.update_incident.assert_awaited_once_with(
            incident_id="123",
            custom_tags=[
                {"key": "env", "value": "prod"},
                {"key": "reviewed", "value": None},
                {"key": "url", "value": "http://example.com"},
            ],
        )

    @pytest.mark.asyncio
    async def test_add_same_key_different_value_coexists(self):
        """
        GIVEN an incident carrying env:prod
        WHEN adding env:staging
        THEN both values are kept; add never evicts a same-key tag
        """
        mock_client = self._client([{"id": "t1", "key": "env", "value": "prod"}])

        params = IncidentCustomTagsParams(incident_id=123, custom_tags=["env:staging"])
        with patch("gg_api_core.tools.manage_incident_custom_tags.get_client", return_value=mock_client):
            await manage_incident_custom_tags(params)

        mock_client.update_incident.assert_awaited_once_with(
            incident_id="123",
            custom_tags=[{"key": "env", "value": "prod"}, {"key": "env", "value": "staging"}],
        )

    @pytest.mark.asyncio
    async def test_empty_final_set_clears_all_tags(self):
        """
        GIVEN an operation whose computed final set is empty (e.g. remove of every tag)
        WHEN managing an incident's tags
        THEN the handler PATCHes custom_tags=[] so the API clears all tags
        """
        mock_client = self._client([{"id": "t1", "key": "env", "value": "prod"}])

        params = IncidentCustomTagsParams(incident_id=123, action="remove", custom_tags=["env:prod"])
        with patch("gg_api_core.tools.manage_incident_custom_tags.get_client", return_value=mock_client):
            await manage_incident_custom_tags(params)

        mock_client.get_incident.assert_awaited_once()
        mock_client.update_incident.assert_awaited_once_with(
            incident_id="123",
            custom_tags=[],
        )
