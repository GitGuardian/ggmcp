"""manage_public_incident: status, assignment and comments on Public Monitoring incidents.

These write to customer workspaces, so the tests pin the endpoint and JSON body for every
action, and that a missing argument blocks the API call entirely.
"""

import pytest

from tests.e2e.harness import TEST_MEMBER_ID, call_tool, sent_body, tool_error_text, tool_output

PUBLIC_INCIDENT = {"id": 103, "status": "TRIGGERED"}


class TestManagePublicIncident:
    @pytest.mark.parametrize(
        ("arguments", "expected_path", "expected_body"),
        [
            pytest.param(
                {"action": "resolve", "resolve_reason": "revoked"},
                "/public-incidents/secrets/103/resolve",
                {"resolve_reason": "revoked"},
                id="resolve",
            ),
            pytest.param(
                {"action": "ignore", "ignore_reason": "ignore_actor"},
                "/public-incidents/secrets/103/ignore",
                {"ignore_reason": "ignore_actor"},
                id="ignore",
            ),
            pytest.param({"action": "reopen"}, "/public-incidents/secrets/103/reopen", None, id="reopen"),
            pytest.param(
                {"action": "assign", "assignee_member_id": 42},
                "/public-incidents/secrets/103/assign",
                {"member_id": 42},
                id="assign-by-member-id",
            ),
            pytest.param(
                {"action": "assign", "assignee_email": "ada@example.com"},
                "/public-incidents/secrets/103/assign",
                {"email": "ada@example.com"},
                id="assign-by-email",
            ),
            pytest.param(
                {"action": "assign", "mine": True},
                "/public-incidents/secrets/103/assign",
                {"member_id": TEST_MEMBER_ID},
                id="assign-to-me",
            ),
        ],
    )
    async def test_each_action_posts_to_its_endpoint(
        self, mcp_client, gg_api, mock_token_scopes, arguments, expected_path, expected_body
    ):
        """
        GIVEN a public incident and an action with what it needs
        WHEN manage_public_incident is called
        THEN the action's endpoint is POSTed with exactly the expected body, and the API answer is returned
        """
        route = gg_api.post(expected_path).respond(200, json=PUBLIC_INCIDENT)

        result = await call_tool(mcp_client, "manage_public_incident", {"incident_id": 103, **arguments})

        assert route.called
        if expected_body is None:
            assert route.calls.last.request.content == b""
        else:
            assert sent_body(route) == expected_body
        assert tool_output(result) == PUBLIC_INCIDENT

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
            pytest.param({"action": "resolve"}, "resolve_reason is required", id="resolve-without-reason"),
            pytest.param({"action": "ignore"}, "ignore_reason is required", id="ignore-without-reason"),
            pytest.param({"action": "assign"}, "exactly one of", id="assign-without-assignee"),
            pytest.param(
                {"action": "assign", "mine": True, "assignee_member_id": 42}, "exactly one of", id="assign-twice"
            ),
            pytest.param({"action": "add_comment"}, "comment is required", id="comment-without-text"),
            pytest.param(
                {"action": "edit_comment", "comment": "x"}, "comment_id is required", id="edit-without-comment-id"
            ),
            pytest.param(
                {"action": "add_comment", "comment": "x", "comment_id": 9},
                "comment_id must not be provided",
                id="add-with-comment-id",
            ),
            pytest.param(
                {"action": "resolve", "resolve_reason": "test_credential"},
                "resolve_reason",
                id="internal-reason-on-a-public-incident",
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

    async def test_an_email_no_member_has_gets_guidance_without_repeating_it(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN an email the API rejects with a 400
        WHEN manage_public_incident assigns by that email
        THEN the error explains the email likely matches no member, and does not repeat the address
        """
        gg_api.post("/public-incidents/secrets/103/assign").respond(400, json={"detail": "Invalid payload."})

        result = await call_tool(
            mcp_client,
            "manage_public_incident",
            {"incident_id": 103, "action": "assign", "assignee_email": "nobody@example.com"},
        )

        error = tool_error_text(result)
        assert "no member of this workspace has that email" in error
        assert "nobody@example.com" not in error

    async def test_it_needs_the_incidents_write_scope(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token with incidents:read but not incidents:write
        WHEN manage_public_incident is called
        THEN it is refused for the missing scope, and the API is never called
        """
        mock_token_scopes(scopes=["incidents:read"])
        route = gg_api.post("/public-incidents/secrets/103/reopen").respond(200, json=PUBLIC_INCIDENT)

        result = await call_tool(mcp_client, "manage_public_incident", {"incident_id": 103, "action": "reopen"})

        assert result["isError"] is True
        assert "incidents:write" in tool_error_text(result)
        assert not route.called
