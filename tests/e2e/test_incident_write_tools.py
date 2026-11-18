"""manage_incident_comment: adding and editing comments on internal incidents.

The tool writes to customer workspaces, so the tests pin the exact endpoint
and JSON body for every action.
"""

from tests.e2e.harness import call_tool, rpc, rpc_result, sent_body, tool_output


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
