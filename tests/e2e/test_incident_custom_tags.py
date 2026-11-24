"""Custom tag tools: add or remove one tag on an incident, and list the workspace's tags.

The API only replaces an incident's whole tag set, so the tests pin that each tool writes
back every tag it did not mean to change, and writes nothing when nothing changes.
"""

import json

import httpx
import pytest

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output

INTERNAL = "/incidents/secrets/42"
PUBLIC = "/public-incidents/secrets/42"
TEAM_TAG = {"id": "0b9c7a8e-6a55-4a1d-9b5e-3d2f1c0a9e11", "key": "team", "value": "payments"}


def _mock_internal(gg_api, tags):
    """The internal incident with these tags, and its PATCH answering with the tags sent."""
    gg_api.get(INTERNAL).respond(200, json={"id": 42, "custom_tags": tags})
    return gg_api.patch(INTERNAL).mock(
        side_effect=lambda request: httpx.Response(200, json={"id": 42, "custom_tags": _sent(request)})
    )


def _mock_public(gg_api, tags):
    gg_api.get(PUBLIC).respond(200, json={"id": 42, "custom_tags": tags})
    return gg_api.post(f"{PUBLIC}/set_custom_tags").mock(
        side_effect=lambda request: httpx.Response(200, json={"id": 42, "custom_tags": _sent(request)})
    )


def _sent(request: httpx.Request) -> list:
    return json.loads(request.content)["custom_tags"]


class TestAddCustomTag:
    async def test_adding_a_tag_keeps_the_incidents_other_tags(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an internal incident tagged team:payments
        WHEN add_internal_incident_custom_tag adds env:prod
        THEN the incident is written back with both tags, and the result says it changed
        """
        write = _mock_internal(gg_api, [TEAM_TAG])

        result = await call_tool(
            mcp_client, "add_internal_incident_custom_tag", {"incident_id": 42, "key": "env", "value": "prod"}
        )

        assert sent_body(write) == {
            "custom_tags": [{"key": "team", "value": "payments"}, {"key": "env", "value": "prod"}]
        }
        assert tool_output(result) == {
            "incident_kind": "internal",
            "incident_id": 42,
            "action": "add",
            "changed": True,
            "custom_tags": [{"key": "team", "value": "payments"}, {"key": "env", "value": "prod"}],
        }

    async def test_a_key_only_tag_is_sent_without_a_value(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an internal incident with no tags
        WHEN add_internal_incident_custom_tag adds the key urgent with no value
        THEN the tag is written with a null value
        """
        write = _mock_internal(gg_api, [])

        await call_tool(mcp_client, "add_internal_incident_custom_tag", {"incident_id": 42, "key": "urgent"})

        assert sent_body(write) == {"custom_tags": [{"key": "urgent", "value": None}]}

    async def test_adding_a_tag_the_incident_has_writes_nothing(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an internal incident already tagged team:payments
        WHEN add_internal_incident_custom_tag adds team:payments
        THEN nothing is written, and the result says nothing changed
        """
        write = _mock_internal(gg_api, [TEAM_TAG])

        result = await call_tool(
            mcp_client, "add_internal_incident_custom_tag", {"incident_id": 42, "key": "team", "value": "payments"}
        )

        assert not write.called
        assert tool_output(result)["changed"] is False

    async def test_a_public_tag_is_set_through_its_own_endpoint(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a public incident tagged team:payments
        WHEN add_public_incident_custom_tag adds env:prod
        THEN set_custom_tags receives both tags, and the result names the public incident
        """
        write = _mock_public(gg_api, [TEAM_TAG])

        result = await call_tool(
            mcp_client, "add_public_incident_custom_tag", {"incident_id": 42, "key": "env", "value": "prod"}
        )

        assert sent_body(write) == {
            "custom_tags": [{"key": "team", "value": "payments"}, {"key": "env", "value": "prod"}]
        }
        assert tool_output(result)["incident_kind"] == "public"

    async def test_a_public_tag_needs_a_value(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a public incident, whose tags always have a value
        WHEN add_public_incident_custom_tag is called with a key only
        THEN the call is refused naming value, and nothing is read or written
        """
        write = _mock_public(gg_api, [])

        result = await call_tool(mcp_client, "add_public_incident_custom_tag", {"incident_id": 42, "key": "env"})

        assert "value" in tool_error_text(result)
        assert not write.called


class TestRemoveCustomTag:
    @pytest.mark.parametrize(
        ("arguments", "kept"),
        [
            pytest.param(
                {"key": "env", "value": "prod"},
                [{"key": "team", "value": "payments"}, {"key": "env", "value": "staging"}],
                id="one-value",
            ),
            pytest.param({"key": "env"}, [{"key": "team", "value": "payments"}], id="every-value-of-a-key"),
        ],
    )
    async def test_removing_keeps_the_tags_it_does_not_match(
        self, mcp_client, gg_api, mock_token_scopes, arguments, kept
    ):
        """
        GIVEN an internal incident tagged team:payments, env:prod and env:staging
        WHEN remove_internal_incident_custom_tag removes env:prod, or every env tag
        THEN the incident is written back with only the tags that do not match
        """
        write = _mock_internal(
            gg_api,
            [TEAM_TAG, {"key": "env", "value": "prod"}, {"key": "env", "value": "staging"}],
        )

        result = await call_tool(mcp_client, "remove_internal_incident_custom_tag", {"incident_id": 42, **arguments})

        assert sent_body(write) == {"custom_tags": kept}
        assert tool_output(result)["changed"] is True

    async def test_removing_a_tag_the_incident_lacks_writes_nothing(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a public incident without an env tag
        WHEN remove_public_incident_custom_tag removes env
        THEN nothing is written, and the result says nothing changed
        """
        write = _mock_public(gg_api, [TEAM_TAG])

        result = await call_tool(mcp_client, "remove_public_incident_custom_tag", {"incident_id": 42, "key": "env"})

        assert not write.called
        assert tool_output(result)["changed"] is False


class TestTagWriteFailures:
    async def test_a_write_that_times_out_says_how_to_check(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN a tag write that times out, which the API may have applied
        WHEN add_internal_incident_custom_tag is called
        THEN the error says the change may or may not have been applied, and to read the incident
        """
        gg_api.get(INTERNAL).respond(200, json={"id": 42, "custom_tags": []})
        gg_api.patch(INTERNAL).mock(side_effect=httpx.ReadTimeout("timed out"))

        result = await call_tool(
            mcp_client, "add_internal_incident_custom_tag", {"incident_id": 42, "key": "env", "value": "prod"}
        )

        text = tool_error_text(result)
        assert "may or may not have been applied" in text
        assert "get_internal_incident" in text

    @pytest.mark.parametrize(
        "tool",
        [
            "add_internal_incident_custom_tag",
            "remove_internal_incident_custom_tag",
            "add_public_incident_custom_tag",
            "remove_public_incident_custom_tag",
        ],
    )
    async def test_each_needs_the_incidents_write_scope(self, mcp_client, gg_api, mock_token_scopes, tool):
        """
        GIVEN a token with incidents:read but not incidents:write
        WHEN a tag tool is called
        THEN it is refused for the missing scope, and the incident is neither read nor written
        """
        mock_token_scopes(scopes=["incidents:read"])
        incident = gg_api.route(path__startswith="/v1/incidents/secrets/42").respond(200, json={"id": 42})
        public = gg_api.route(path__startswith="/v1/public-incidents/secrets/42").respond(200, json={"id": 42})

        result = await call_tool(mcp_client, tool, {"incident_id": 42, "key": "env", "value": "prod"})

        assert "incidents:write" in tool_error_text(result)
        assert not incident.called
        assert not public.called


class TestListCustomTags:
    async def test_tags_are_listed_with_the_pagination_contract(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN two pages of custom tags
        WHEN list_custom_tags is called with a key and a page size
        THEN the key and page size reach the API, and next_arguments resume at the next page
        """
        route = gg_api.get("/custom_tags").respond(
            200,
            json=[TEAM_TAG],
            headers={"Link": '<https://api.gitguardian.com/v1/custom_tags?cursor=cD0x>; rel="next"'},
        )

        result = await call_tool(mcp_client, "list_custom_tags", {"key": "team", "per_page": 1})

        output = tool_output(result)
        assert dict(route.calls.last.request.url.params) == {"key": "team", "per_page": "1"}
        assert output["custom_tags"] == [TEAM_TAG]
        assert output["next_arguments"] == {"key": "team", "per_page": 1, "cursor": "cD0x"}

    async def test_it_needs_the_custom_tags_read_scope(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token without custom_tags:read
        WHEN list_custom_tags is called
        THEN it is refused for the missing scope
        """
        mock_token_scopes(scopes=["incidents:read"])
        route = gg_api.get("/custom_tags").respond(200, json=[])

        result = await call_tool(mcp_client, "list_custom_tags", {})

        assert "custom_tags:read" in tool_error_text(result)
        assert not route.called
