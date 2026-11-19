"""list_honeytokens and list_detectors."""

from tests.e2e.harness import TEST_MEMBER_ID, call_tool, sent_params, tool_error_text, tool_output

HONEYTOKEN = {"id": "5b0d6f6e-6c2a-4f4b-9d0a-2f3c1e7a9b10", "name": "decoy", "status": "active"}
DETECTOR = {"name": "aws_iam", "display_name": "AWS Keys", "is_active": True}


class TestListHoneytokens:
    async def test_honeytokens_are_listed_without_their_credentials(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN active honeytokens
        WHEN list_honeytokens is called with a status
        THEN the API is asked not to show the credentials, sorted newest first, and the honeytokens are returned
        """
        route = gg_api.get("/honeytokens").respond(200, json=[HONEYTOKEN])

        result = await call_tool(mcp_client, "list_honeytokens", {"status": "active"})

        params = sent_params(route)
        assert params["show_token"] == "false"
        assert params["status"] == "active"
        assert params["ordering"] == "-created_at"
        assert tool_output(result)["honeytokens"] == [HONEYTOKEN]

    async def test_mine_lists_the_honeytokens_the_caller_created(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True
        WHEN list_honeytokens is called
        THEN only the honeytokens the token's member created are asked for
        """
        route = gg_api.get("/honeytokens").respond(200, json=[])

        await call_tool(mcp_client, "list_honeytokens", {"mine": True})

        assert sent_params(route)["creator_id"] == str(TEST_MEMBER_ID)

    async def test_an_answer_the_api_did_not_page_is_paged_by_the_tool(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN /honeytokens answering five honeytokens at once, whatever per_page asks for
        WHEN list_honeytokens is called with page_size 2, then with the next_arguments it returns
        THEN each call returns two honeytokens, in order, until the last one, without the API paging them
        """
        tokens = [{"id": f"hk-{i}", "name": f"decoy-{i}", "status": "active"} for i in range(5)]
        gg_api.get("/honeytokens").respond(200, json=tokens)

        seen = []
        arguments = {"page_size": 2}
        for _ in range(5):
            output = tool_output(await call_tool(mcp_client, "list_honeytokens", arguments))
            assert len(output["honeytokens"]) <= 2
            seen.extend(token["id"] for token in output["honeytokens"])
            if not output["has_more"]:
                break
            arguments = output["next_arguments"]

        assert seen == [f"hk-{i}" for i in range(5)]
        assert output["stop_reason"] == "end"

    async def test_it_needs_the_honeytokens_read_scope(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token without honeytokens:read
        WHEN list_honeytokens is called
        THEN it is refused naming the scope
        """
        mock_token_scopes(scopes=["incidents:read"])

        result = await call_tool(mcp_client, "list_honeytokens", {})

        assert "honeytokens:read" in tool_error_text(result)


class TestListDetectors:
    async def test_detectors_are_searched_with_the_pagination_contract(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN detectors across two pages
        WHEN list_detectors searches enabled detectors by name
        THEN the filters reach /secret_detectors under the API's names, and next_arguments resume with them
        """
        route = gg_api.get("/secret_detectors").respond(
            200,
            json=[DETECTOR],
            headers={"Link": '<https://api.gitguardian.com/v1/secret_detectors?cursor=cD0x>; rel="next"'},
        )

        result = await call_tool(mcp_client, "list_detectors", {"search": "aws", "active": True, "page_size": 1})

        assert sent_params(route) == {"search": "aws", "is_active": "true", "per_page": "1"}
        output = tool_output(result)
        assert output["detectors"] == [DETECTOR]
        assert output["next_arguments"] == {"search": "aws", "active": True, "page_size": 1, "cursor": "cD0x"}
