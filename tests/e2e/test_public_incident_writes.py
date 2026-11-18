"""manage_public_incident: comments on Public Monitoring incidents.

These write to customer workspaces, so the tests pin the endpoint and JSON body for every
action, and that a missing argument blocks the API call entirely.
"""

import pytest

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output

PUBLIC_INCIDENT = {"id": 103, "status": "TRIGGERED"}


class TestManagePublicIncident:
    async def test_add_comment_posts_a_note(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=add_comment
        WHEN manage_public_incident is called
        THEN a note is POSTed on the public incident with the comment as its only field
        """
        note = {"id": 9, "comment": "Reported to the repository owner"}
        route = gg_api.post("/public-incidents/secrets/103/notes").respond(201, json=note)

        result = await call_tool(
            mcp_client,
            "manage_public_incident",
            {"incident_id": 103, "action": "add_comment", "comment": "Reported to the repository owner"},
        )

        assert sent_body(route) == {"comment": "Reported to the repository owner"}
        assert tool_output(result) == note

    async def test_edit_comment_patches_the_note(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=edit_comment with a comment id
        WHEN manage_public_incident is called
        THEN that note is PATCHed with the new comment
        """
        note = {"id": 9, "comment": "Owner removed the file"}
        route = gg_api.patch("/public-incidents/secrets/103/notes/9").respond(200, json=note)

        result = await call_tool(
            mcp_client,
            "manage_public_incident",
            {"incident_id": 103, "action": "edit_comment", "comment_id": 9, "comment": "Owner removed the file"},
        )

        assert sent_body(route) == {"comment": "Owner removed the file"}
        assert tool_output(result) == note

    @pytest.mark.parametrize(
        ("arguments", "message"),
        [
            pytest.param({"action": "add_comment"}, "comment is required", id="comment-without-text"),
            pytest.param(
                {"action": "edit_comment", "comment": "x"}, "comment_id is required", id="edit-without-comment-id"
            ),
            pytest.param(
                {"action": "add_comment", "comment": "x", "comment_id": 9},
                "comment_id must not be provided",
                id="add-with-comment-id",
            ),
        ],
    )
    async def test_missing_or_wrong_arguments_block_the_call(
        self, mcp_client, gg_api, mock_token_scopes, arguments, message
    ):
        """
        GIVEN an action without what it needs, or with an argument it does not take
        WHEN manage_public_incident is called
        THEN the call fails with an argument error naming the problem, and the API is never called
        """
        route = gg_api.route(path__startswith="/v1/public-incidents/").respond(200, json=PUBLIC_INCIDENT)

        result = await call_tool(mcp_client, "manage_public_incident", {"incident_id": 103, **arguments})

        assert result["isError"] is True
        assert message in tool_error_text(result)
        assert not route.called

    async def test_it_needs_the_incidents_write_scope(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token with incidents:read but not incidents:write
        WHEN manage_public_incident is called
        THEN it is refused for the missing scope, and the API is never called
        """
        mock_token_scopes(scopes=["incidents:read"])
        route = gg_api.post("/public-incidents/secrets/103/notes").respond(201, json={"id": 9})

        result = await call_tool(
            mcp_client, "manage_public_incident", {"incident_id": 103, "action": "add_comment", "comment": "x"}
        )

        assert result["isError"] is True
        assert "incidents:write" in tool_error_text(result)
        assert not route.called
