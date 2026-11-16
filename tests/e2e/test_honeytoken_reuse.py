"""generate_honeytoken creates a live decoy only on purpose (SI-4073).

With new_token=False the caller asked to reuse a honeytoken, so a new one is
created only when the reuse lookup succeeded and found none.
"""

from tests.e2e.harness import TEST_MEMBER_ID, call_tool, tool_error_text, tool_output

CREATED = {"id": "8e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b", "name": "decoy", "status": "ACTIVE", "type": "AWS"}
EXISTING = {
    "id": "5b0d6f6e-6c2a-4f4b-9d0a-2f3c1e7a9b10",
    "name": "earlier-decoy",
    "status": "ACTIVE",
    "type": "AWS",
    "token": {"access_token_id": "x"},
}


def _reuse(name: str = "decoy") -> dict:
    return {"name": name, "new_token": False}


class TestHoneytokenReuse:
    async def test_a_failed_lookup_creates_nothing(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token that cannot list honeytokens (the API answers 403)
        WHEN generate_honeytoken is asked to reuse one
        THEN the call fails saying nothing was created, and no honeytoken is created
        """
        gg_api.get("/honeytokens").respond(
            403, json={"detail": "Token is missing the following scope: honeytokens:read"}
        )
        create = gg_api.post("/honeytokens").respond(201, json=CREATED)

        result = await call_tool(mcp_client, "generate_honeytoken", _reuse())

        error = tool_error_text(result)
        assert "No honeytoken was created" in error
        assert "honeytokens:read" in error
        assert not create.called

    async def test_a_token_without_a_member_creates_nothing(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token that is not tied to a workspace member
        WHEN generate_honeytoken is asked to reuse one
        THEN the call fails pointing at new_token=true, and no honeytoken is created
        """
        mock_token_scopes(member_id=None)
        create = gg_api.post("/honeytokens").respond(201, json=CREATED)

        result = await call_tool(mcp_client, "generate_honeytoken", _reuse())

        assert "new_token=true" in tool_error_text(result)
        assert not create.called

    async def test_the_most_recent_active_honeytoken_is_reused(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the caller has an active honeytoken
        WHEN generate_honeytoken is asked to reuse one
        THEN that honeytoken is returned and none is created
        """
        lookup = gg_api.get("/honeytokens").respond(200, json=[{"id": "5b0d6f6e-6c2a-4f4b-9d0a-2f3c1e7a9b10"}])
        gg_api.get("/honeytokens/5b0d6f6e-6c2a-4f4b-9d0a-2f3c1e7a9b10").respond(200, json=EXISTING)
        create = gg_api.post("/honeytokens").respond(201, json=CREATED)

        result = await call_tool(mcp_client, "generate_honeytoken", _reuse())

        assert tool_output(result)["id"] == "5b0d6f6e-6c2a-4f4b-9d0a-2f3c1e7a9b10"
        assert not create.called
        # The API rejects any other casing of the status filter with a 400.
        params = lookup.calls.last.request.url.params
        assert params["status"] == "active"
        assert params["creator_id"] == str(TEST_MEMBER_ID)
        assert params["ordering"] == "-created_at"

    async def test_a_caller_with_no_honeytoken_gets_a_new_one(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the lookup succeeds and the caller has no active honeytoken
        WHEN generate_honeytoken is asked to reuse one
        THEN a new honeytoken is created with the requested name
        """
        gg_api.get("/honeytokens").respond(200, json=[])
        create = gg_api.post("/honeytokens").respond(201, json=CREATED)

        result = await call_tool(mcp_client, "generate_honeytoken", _reuse())

        assert create.called
        assert tool_output(result)["id"] == "8e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
