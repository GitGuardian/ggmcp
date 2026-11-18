"""get_my_identity: who the token belongs to, and what the token is."""

from tests.e2e.harness import EXPECTED_SCOPES, TEST_MEMBER_ID, call_tool, tool_output

MEMBER = {
    "id": TEST_MEMBER_ID,
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "access_level": "manager",
    "active": True,
    "created_at": "2026-01-01T00:00:00Z",
}


class TestGetMyIdentity:
    async def test_the_member_and_the_token_are_described(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a personal access token tied to a member
        WHEN get_my_identity is called
        THEN it returns the workspace, the token's scopes, and the member's name, email and role
        """
        member_route = gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json=MEMBER)

        result = await call_tool(mcp_client, "get_my_identity", {})

        assert member_route.called
        assert tool_output(result) == {
            "workspace_id": 1,
            "token": {
                "name": "e2e token",
                "type": "personal_access_token",
                "status": "active",
                "scopes": list(EXPECTED_SCOPES),
                "created_at": None,
                "expire_at": None,
            },
            "member": {
                "id": TEST_MEMBER_ID,
                "name": "Ada Lovelace",
                "email": "ada@example.com",
                "access_level": "manager",
                "active": True,
            },
            "member_unavailable_reason": None,
        }

    async def test_a_token_without_a_member_still_describes_the_token(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token not tied to a member, such as a service account's
        WHEN get_my_identity is called
        THEN the token is described, no member is looked up, and the result says why there is no member
        """
        mock_token_scopes(member_id=None)
        member_route = gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json=MEMBER)

        result = await call_tool(mcp_client, "get_my_identity", {})

        output = tool_output(result)
        assert not member_route.called
        assert output["token"]["name"] == "e2e token"
        assert output["member"] is None
        assert "not tied to a workspace member" in output["member_unavailable_reason"]

    async def test_a_token_without_members_read_still_describes_the_token(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token the API refuses member details to, with a 403
        WHEN get_my_identity is called
        THEN the token is described, and the result names the members:read scope it lacks
        """
        gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(403, json={"detail": "Insufficient scope."})

        result = await call_tool(mcp_client, "get_my_identity", {})

        output = tool_output(result)
        assert output["token"]["scopes"] == list(EXPECTED_SCOPES)
        assert output["member"] is None
        assert "members:read" in output["member_unavailable_reason"]

    async def test_any_token_can_call_it(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token with only the scan scope
        WHEN get_my_identity is called
        THEN it runs: describing the caller needs no scope
        """
        mock_token_scopes(scopes=["scan"])
        gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json=MEMBER)

        result = await call_tool(mcp_client, "get_my_identity", {})

        assert result["isError"] is False
        assert tool_output(result)["token"]["scopes"] == ["scan"]
