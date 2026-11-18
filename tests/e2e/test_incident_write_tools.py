"""Mutating incident tools: status changes, assignment and comments.

These tools write to customer workspaces, so the tests pin the exact endpoint
and JSON body for every action, and that guard rails (required reasons) block
the HTTP call entirely.
"""

import logging

import pytest

from tests.e2e.harness import call_tool, rpc, rpc_result, sent_body, tool_error_text, tool_output


class TestManagePrivateIncident:
    @pytest.mark.parametrize(
        ("arguments", "expected_path", "expected_body"),
        [
            pytest.param(
                {"incident_id": 42, "action": "unassign"},
                "/incidents/secrets/42/unassign",
                None,
                id="unassign-sends-no-body",
            ),
        ],
    )
    async def test_each_action_hits_its_endpoint_with_the_exact_body(
        self, mcp_client, gg_api, mock_token_scopes, arguments, expected_path, expected_body
    ):
        """
        GIVEN a private incident action
        WHEN manage_private_incident is called
        THEN the matching status endpoint receives a POST with exactly the
             documented body and the API response is returned verbatim
        """
        route = gg_api.post(expected_path).respond(200, json={"id": 42, "status": "UPDATED"})

        result = await call_tool(mcp_client, "manage_private_incident", arguments)

        assert route.called
        assert sent_body(route) == expected_body
        assert tool_output(result) == {"id": 42, "status": "UPDATED"}


CRAFTED_INCIDENT_IDS = [
    pytest.param("1/../../members/5", id="path-traversal"),
    pytest.param("42?show_token=true", id="query-injection"),
    pytest.param("abc", id="not-a-number"),
    pytest.param("4\u0662", id="non-ascii-digit"),
]

ID_IN_PATH_CALLS = [
    pytest.param("assign_incident", {"mine": True}, id="assign_incident"),
    pytest.param("manage_private_incident", {"action": "unassign"}, id="manage_private_incident"),
]


@pytest.mark.parametrize("incident_id", CRAFTED_INCIDENT_IDS)
@pytest.mark.parametrize(("tool_name", "arguments"), ID_IN_PATH_CALLS)
async def test_an_incident_id_that_is_not_a_number_never_reaches_the_api(
    mcp_client, gg_api, mock_token_scopes, tool_name, arguments, incident_id
):
    """
    GIVEN an incident_id string that is not made of digits
    WHEN a tool that places it in the URL path is called
    THEN the call fails validation and no incident endpoint is requested
    """
    result = await call_tool(mcp_client, tool_name, {"incident_id": incident_id, **arguments})

    assert "must be a numeric ID" in tool_error_text(result)
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


@pytest.mark.parametrize(("tool_name", "arguments"), ID_IN_PATH_CALLS)
async def test_a_numeric_string_incident_id_is_still_accepted(
    mcp_client, gg_api, mock_token_scopes, tool_name, arguments
):
    """
    GIVEN an incident_id sent as a string of digits, as some clients do
    WHEN a tool that places it in the URL path is called
    THEN the request goes to that incident's endpoint
    """
    endpoint = "/incidents/secrets/42/assign" if tool_name == "assign_incident" else "/incidents/secrets/42/unassign"
    route = gg_api.post(endpoint).respond(200, json={"id": 42})

    await call_tool(mcp_client, tool_name, {"incident_id": "42", **arguments})

    assert route.called


class TestAssignIncident:
    async def test_mine_assigns_to_the_callers_member_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True
        WHEN assign_incident is called
        THEN the caller is resolved via /api_tokens/self and the assign body
             carries only the stringified member id
        """
        route = gg_api.post("/incidents/secrets/42/assign").respond(200, json={"id": 42, "assignee_id": 4242})

        result = await call_tool(mcp_client, "assign_incident", {"incident_id": 42, "mine": True})

        assert sent_body(route) == {"member_id": "4242"}
        output = tool_output(result)
        assert output["assignee_id"] == 4242
        assert output["success"] is True

    async def test_an_email_assignment_sends_only_the_email(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an email
        WHEN assign_incident is called
        THEN the assign body carries only the email, and the member the API resolved is returned
        """
        route = gg_api.post("/incidents/secrets/42/assign").respond(200, json={"id": 42, "assignee_id": 4242})

        result = await call_tool(mcp_client, "assign_incident", {"incident_id": 42, "email": "dev@example.com"})

        assert sent_body(route) == {"email": "dev@example.com"}
        assert tool_output(result)["assignee_id"] == 4242

    async def test_an_email_no_member_has_gets_a_hint_that_does_not_repeat_it(
        self, mcp_client, gg_api, mock_token_scopes, caplog
    ):
        """
        GIVEN an email the API refuses with its bare "Invalid payload." 400
        WHEN assign_incident is called
        THEN the error says no member likely has that address and how to proceed, and neither it nor any log repeats it
        """
        gg_api.post("/incidents/secrets/42/assign").respond(400, json={"detail": "Invalid payload."})

        with caplog.at_level(logging.DEBUG):
            result = await call_tool(mcp_client, "assign_incident", {"incident_id": 42, "email": "nobody@example.com"})

        error = tool_error_text(result)
        assert "Invalid payload" in error
        assert "no member of this workspace has that email address" in error
        assert "nobody@example.com" not in error
        assert [r.getMessage() for r in caplog.records if "nobody@example.com" in r.getMessage()] == []

    async def test_a_member_id_assignment_refusal_gets_no_email_hint(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a member ID the API refuses with a 400
        WHEN assign_incident is called
        THEN the error carries the API's reason only, with no hint about email addresses
        """
        gg_api.post("/incidents/secrets/42/assign").respond(400, json={"detail": "Invalid payload."})

        result = await call_tool(mcp_client, "assign_incident", {"incident_id": 42, "assignee_member_id": 7})

        error = tool_error_text(result)
        assert "Invalid payload" in error
        assert "email" not in error


class TestManageIncidentComment:
    async def test_add_posts_a_note_with_the_comment(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=add
        WHEN manage_incident_comment is called
        THEN a note is POSTed on the incident with the comment as its only field
             and the created note is returned
        """
        note = {"id": 9, "incident_id": 77, "comment": "Rotating the key today"}
        route = gg_api.post("/incidents/secrets/77/notes").respond(201, json=note)

        result = await call_tool(
            mcp_client,
            "manage_incident_comment",
            {"incident_id": 77, "action": "add", "comment": "Rotating the key today"},
        )

        assert sent_body(route) == {"comment": "Rotating the key today"}
        assert tool_output(result) == note

    async def test_edit_patches_the_existing_note(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=edit with a comment id
        WHEN manage_incident_comment is called
        THEN that note is PATCHed with the new comment
        """
        note = {"id": 9, "incident_id": 77, "comment": "Key rotated"}
        route = gg_api.patch("/incidents/secrets/77/notes/9").respond(200, json=note)

        result = await call_tool(
            mcp_client,
            "manage_incident_comment",
            {"incident_id": 77, "action": "edit", "comment_id": 9, "comment": "Key rotated"},
        )

        assert sent_body(route) == {"comment": "Key rotated"}
        assert tool_output(result) == note

    async def test_the_id_add_returns_is_the_comment_id_edit_takes(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN no tool lists an incident's comments
        WHEN a comment is added, then edited with the id the add returned
        THEN the edit PATCHes that note, and the comment_id description says where the id comes from
        """
        gg_api.post("/incidents/secrets/77/notes").respond(201, json={"id": 9, "comment": "Rotating the key"})
        edit = gg_api.patch("/incidents/secrets/77/notes/9").respond(200, json={"id": 9, "comment": "Key rotated"})

        added = tool_output(
            await call_tool(
                mcp_client,
                "manage_incident_comment",
                {"incident_id": 77, "action": "add", "comment": "Rotating the key"},
            )
        )
        await call_tool(
            mcp_client,
            "manage_incident_comment",
            {"incident_id": 77, "action": "edit", "comment_id": added["id"], "comment": "Key rotated"},
        )

        assert edit.called
        tools = rpc_result(await rpc(mcp_client, "tools/list", {}))["tools"]
        schema = next(tool["inputSchema"] for tool in tools if tool["name"] == "manage_incident_comment")
        assert "the id that action 'add' returned" in schema["properties"]["comment_id"]["description"]
