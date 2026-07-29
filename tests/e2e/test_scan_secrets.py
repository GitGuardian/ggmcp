"""scan_secrets: the highest-volume tool of the remote server.

Pins the /multiscan wire contract (documents pass through verbatim, results
come back untouched) and the input-validation and crash behavior around it.
"""

from tests.e2e.harness import assert_authenticated_request, call_tool, sent_body, tool_error_text, tool_output

SCAN_RESULT = {
    "policy_break_count": 1,
    "policies": ["Secrets detection"],
    "policy_breaks": [
        {
            "type": "AWS Keys",
            "policy": "Secrets detection",
            "matches": [{"type": "apikey", "match": "AKIA...", "line_start": 3}],
        }
    ],
}


class TestScanSecrets:
    async def test_documents_are_posted_verbatim_and_results_returned_untouched(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN two documents with filenames
        WHEN scan_secrets is called
        THEN the multiscan API receives the raw document list as JSON body and
             the per-document results are returned verbatim under scan_results
        """
        documents = [
            {"document": "aws_key = 'AKIA...'\n", "filename": "config.py"},
            {"document": "clean file\n", "filename": "README.md"},
        ]
        route = gg_api.post("/multiscan").respond(200, json=[SCAN_RESULT, {"policy_break_count": 0}])

        result = await call_tool(mcp_client, "scan_secrets", {"params": {"documents": documents}})

        assert_authenticated_request(route)
        assert sent_body(route) == documents
        assert tool_output(result) == {"scan_results": [SCAN_RESULT, {"policy_break_count": 0}]}

    async def test_document_without_filename_crashes_before_reaching_the_api(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a document dict carrying only the document key
        WHEN scan_secrets is called
        THEN the call fails with the request-logging crash and no API call is made
        """
        route = gg_api.post("/multiscan").respond(200, json=[SCAN_RESULT])

        result = await call_tool(mcp_client, "scan_secrets", {"params": {"documents": [{"document": "x = 1\n"}]}})

        # TODO(SI-3891): known crash, the client's request-body debug logging
        # does dict(list) on the multiscan payload; single-key documents blow
        # up before the HTTP request is even sent (Sentry R1).
        assert "dictionary update sequence" in tool_error_text(result)
        assert not route.called

    async def test_empty_document_list_is_rejected_without_an_api_call(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an empty documents list
        WHEN scan_secrets is called
        THEN validation fails locally and the API is never contacted
        """
        route = gg_api.post("/multiscan").respond(200, json=[])

        result = await call_tool(mcp_client, "scan_secrets", {"params": {"documents": []}})

        assert "non-empty list" in tool_error_text(result)
        assert not route.called

    async def test_api_rejection_bubbles_up_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API rejecting the batch with 400
        WHEN scan_secrets is called
        THEN the failure surfaces as a tool error naming the status
        """
        gg_api.post("/multiscan").respond(400, json={"detail": "Too many documents."})

        result = await call_tool(
            mcp_client,
            "scan_secrets",
            {"params": {"documents": [{"document": "x", "filename": "x.py"}]}},
        )

        assert "400" in tool_error_text(result)
