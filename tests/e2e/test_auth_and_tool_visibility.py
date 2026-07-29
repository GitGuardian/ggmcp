"""Auth handshake and scope-based tool visibility of the remote MCP server.

These are the behaviors every remote client depends on before any tool runs:
requests without credentials must be rejected with re-auth metadata, and
tools/list must reflect the token's actual scopes (fetched live from the
GitGuardian API).
"""

import asyncio

import httpx

from tests.e2e.harness import (
    EXPECTED_SCOPES,
    TEST_PAT,
    assert_authenticated_request,
    call_tool,
    list_tool_names,
    mcp_headers,
    rpc,
    rpc_result,
    token_info,
    tool_output,
    unwrap_result,
)

EXPECTED_FULL_TOOL_CATALOG = {
    "assign_incident",
    "assign_public_incident",
    "count_incidents",
    "create_code_fix_request",
    "find_current_source_id",
    "generate_honeytoken",
    "get_authenticated_user_info",
    "get_current_token_info",
    "get_incident",
    "get_member",
    "get_public_incident",
    "get_remediation_workflow",
    "list_detectors",
    "list_honeytokens",
    "list_incident_activity_logs",
    "list_incident_comments",
    "list_incident_members",
    "list_incident_teams",
    "list_incidents",
    "list_public_incident_activity_logs",
    "list_public_incident_comments",
    "list_public_incidents",
    "list_public_occurrences",
    "list_repo_occurrences",
    "list_sources",
    "list_users",
    "manage_incident_comment",
    "manage_private_incident",
    "manage_public_incident_comment",
    "read_custom_tags",
    "remediate_secret_incidents",
    "revoke_current_token",
    "revoke_secret",
    "scan_secrets",
    "update_incident_severity",
    "update_or_create_incident_custom_tags",
    "update_public_incident_status",
    "write_custom_tags",
}

EXPECTED_SCAN_ONLY_TOOL_CATALOG = {
    "get_authenticated_user_info",
    "list_detectors",
    "revoke_current_token",
    "scan_secrets",
}


class TestProtocolHandshake:
    async def test_initialize_returns_the_production_server_identity_and_capabilities(self, mcp_client, gg_api):
        """
        GIVEN an authenticated MCP client beginning a protocol session
        WHEN it sends initialize with a supported protocol version
        THEN the server identifies itself and advertises its tool capability
        """
        response = await rpc(
            mcp_client,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e-client", "version": "1.0.0"},
            },
        )

        result = rpc_result(response)
        assert result["protocolVersion"] == "2025-06-18"
        assert result["serverInfo"]["name"] == "GitGuardian"
        assert "tools" in result["capabilities"]
        assert result["instructions"]
        assert not gg_api.calls


class TestUnauthenticatedRequests:
    async def test_missing_authorization_header_is_rejected_with_reauth_metadata(self, mcp_client, gg_api):
        """
        GIVEN the remote server
        WHEN a tools/list request arrives without an Authorization header
        THEN it is rejected with HTTP 401 and a WWW-Authenticate header pointing
             to both the protected-resource and authorization-server metadata,
             and the GitGuardian API is never contacted
        """
        response = await rpc(mcp_client, "tools/list", headers={"Accept": "application/json, text/event-stream"})

        assert response.status_code == 401
        www_authenticate = response.headers["www-authenticate"]
        assert "resource_metadata=" in www_authenticate
        assert 'as_metadata="https://mcp.gitguardian.com/.well-known/oauth-authorization-server"' in www_authenticate
        assert not gg_api.calls


class TestScopeBasedToolVisibility:
    async def test_full_scopes_expose_the_whole_catalog(self, mcp_client, mock_token_scopes):
        """
        GIVEN a token holding every GitGuardian scope
        WHEN tools/list is requested
        THEN read, write, scan and honeytoken tools are all visible
        """
        names = await list_tool_names(mcp_client)

        assert names == EXPECTED_FULL_TOOL_CATALOG

    async def test_token_scopes_are_fetched_from_the_api_with_the_callers_token(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a bearer token sent by the MCP client
        WHEN tools/list is requested
        THEN the server resolves scopes via GET /api_tokens/self, forwarding
             the caller's token in GitGuardian's Token scheme
        """
        await list_tool_names(mcp_client)

        token_requests = [call.request for call in gg_api.calls if call.request.url.path == "/v1/api_tokens/self"]
        assert token_requests, "expected a live scope fetch against /api_tokens/self"
        assert token_requests[0].headers["Authorization"] == f"Token {TEST_PAT}"
        assert token_requests[0].headers["X-Privacy-Mode"] == "true"

    async def test_scan_only_token_hides_scope_gated_tools(self, mcp_client, mock_token_scopes):
        """
        GIVEN a token limited to the scan scope
        WHEN tools/list is requested
        THEN only scan-gated and ungated tools remain visible
        """
        mock_token_scopes(scopes=["scan"])

        names = await list_tool_names(mcp_client)

        assert "scan_secrets" in names
        assert "list_detectors" in names
        # get_authenticated_user_info has no required_scopes, so it always shows
        assert "get_authenticated_user_info" in names
        assert "list_incidents" not in names
        assert "manage_private_incident" not in names
        assert "list_sources" not in names
        assert "get_current_token_info" not in names

    async def test_incidents_read_token_gets_read_but_not_write_tools(self, mcp_client, mock_token_scopes):
        """
        GIVEN a token with incidents:read but not incidents:write
        WHEN tools/list is requested
        THEN incident read tools are visible and incident write tools are hidden
        """
        mock_token_scopes(scopes=["incidents:read"])

        names = await list_tool_names(mcp_client)

        assert {"list_incidents", "count_incidents", "get_incident", "get_remediation_workflow"} <= names
        assert "manage_private_incident" not in names
        assert "assign_incident" not in names
        assert "update_incident_severity" not in names
        # remediate needs sources:read on top of incidents:read
        assert "remediate_secret_incidents" not in names

    async def test_tool_visibility_is_isolated_between_tenants_on_one_server(self, mcp_client, gg_api):
        """
        GIVEN two tenants with different token scopes using the same server
        WHEN each tenant requests tools/list
        THEN each receives only the catalog authorized by its own token
        """

        def token_response(request: httpx.Request) -> httpx.Response:
            authorization = request.headers["Authorization"]
            if authorization == "Token full-scope-token":
                return httpx.Response(200, json=token_info(EXPECTED_SCOPES))
            if authorization == "Token scan-only-token":
                return httpx.Response(200, json=token_info(["scan"]))
            raise AssertionError(f"Unexpected tenant token: {authorization}")

        token_route = gg_api.get("/api_tokens/self").mock(side_effect=token_response)

        first_full_catalog = await list_tool_names(mcp_client, headers=mcp_headers("full-scope-token"))
        scan_catalog = await list_tool_names(mcp_client, headers=mcp_headers("scan-only-token"))
        second_full_catalog = await list_tool_names(mcp_client, headers=mcp_headers("full-scope-token"))

        assert first_full_catalog == EXPECTED_FULL_TOOL_CATALOG
        assert scan_catalog == EXPECTED_SCAN_ONLY_TOOL_CATALOG
        assert second_full_catalog == EXPECTED_FULL_TOOL_CATALOG
        assert token_route.call_count == 3

    async def test_concurrent_requests_keep_tenant_context_isolated(self, mcp_client, gg_api):
        """
        GIVEN two tenants making overlapping discovery and tool requests
        WHEN both requests execute concurrently on the same server instance
        THEN each catalog and outbound API call retains its own tenant token
        """
        scope_requests_ready = asyncio.Event()
        seen_scope_tokens: set[str] = set()

        async def concurrent_token_response(request: httpx.Request) -> httpx.Response:
            authorization = request.headers["Authorization"]
            seen_scope_tokens.add(authorization)
            if seen_scope_tokens == {"Token full-scope-token", "Token scan-only-token"}:
                scope_requests_ready.set()
            try:
                await asyncio.wait_for(scope_requests_ready.wait(), timeout=1)
            except TimeoutError as exc:
                raise AssertionError(
                    f"Concurrent scope requests did not overlap; observed tokens: {sorted(seen_scope_tokens)}"
                ) from exc
            scopes = EXPECTED_SCOPES if authorization == "Token full-scope-token" else ["scan"]
            return httpx.Response(200, json=token_info(scopes))

        token_route = gg_api.get("/api_tokens/self").mock(side_effect=concurrent_token_response)

        full_catalog, scan_catalog = await asyncio.wait_for(
            asyncio.gather(
                list_tool_names(
                    mcp_client,
                    headers=mcp_headers("full-scope-token"),
                    request_id=101,
                ),
                list_tool_names(
                    mcp_client,
                    headers=mcp_headers("scan-only-token"),
                    request_id=102,
                ),
            ),
            timeout=2,
        )

        assert full_catalog == EXPECTED_FULL_TOOL_CATALOG
        assert scan_catalog == EXPECTED_SCAN_ONLY_TOOL_CATALOG
        assert token_route.call_count == 2

        tool_requests_ready = asyncio.Event()
        seen_tool_names: set[str] = set()

        async def incident_response(_request: httpx.Request) -> httpx.Response:
            seen_tool_names.add("incident")
            if seen_tool_names == {"incident", "scan"}:
                tool_requests_ready.set()
            try:
                await asyncio.wait_for(tool_requests_ready.wait(), timeout=1)
            except TimeoutError as exc:
                raise AssertionError(
                    f"Concurrent tool requests did not overlap; observed tools: {sorted(seen_tool_names)}"
                ) from exc
            return httpx.Response(200, json={"id": 77})

        async def scan_response(_request: httpx.Request) -> httpx.Response:
            seen_tool_names.add("scan")
            if seen_tool_names == {"incident", "scan"}:
                tool_requests_ready.set()
            try:
                await asyncio.wait_for(tool_requests_ready.wait(), timeout=1)
            except TimeoutError as exc:
                raise AssertionError(
                    f"Concurrent tool requests did not overlap; observed tools: {sorted(seen_tool_names)}"
                ) from exc
            return httpx.Response(200, json=[{"policy_break_count": 0}])

        incident_route = gg_api.get("/incidents/secrets/77").mock(side_effect=incident_response)
        scan_route = gg_api.post("/multiscan").mock(side_effect=scan_response)

        incident_result, scan_result = await asyncio.wait_for(
            asyncio.gather(
                call_tool(
                    mcp_client,
                    "get_incident",
                    {"params": {"incident_id": 77}},
                    headers=mcp_headers("full-scope-token"),
                    request_id=201,
                ),
                call_tool(
                    mcp_client,
                    "scan_secrets",
                    {"params": {"documents": [{"document": "x = 1", "filename": "x.py"}]}},
                    headers=mcp_headers("scan-only-token"),
                    request_id=202,
                ),
            ),
            timeout=2,
        )

        assert tool_output(incident_result) == {"incident": {"id": 77}}
        assert tool_output(scan_result) == {"scan_results": [{"policy_break_count": 0}]}
        assert_authenticated_request(incident_route, "full-scope-token")
        assert_authenticated_request(scan_route, "scan-only-token")

    async def test_a_scope_hidden_tool_is_still_callable(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a scan-only token, for which list_incidents is hidden
        WHEN list_incidents is called anyway
        THEN the tool executes and its request is forwarded to the API
        """
        mock_token_scopes(scopes=["scan"])
        route = gg_api.get("/incidents-for-mcp").respond(200, json={"results": [], "next": None, "previous": None})

        result = await call_tool(mcp_client, "list_incidents", {"params": {}})

        # Scope filtering only controls visibility; enforcement happens at the
        # GitGuardian API, which rejects tokens lacking the scope.
        assert route.called
        assert unwrap_result(result)["incidents"] == []


class TestPerRequestScopeCost:
    async def test_tool_dispatch_fetches_scopes_once_then_reuses_a_shared_cache(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the stateless remote deployment
        WHEN the same tool is called twice
        THEN the first dispatch resolves scopes upstream (tool-cache refresh)
             and the second reuses the process-wide cache
        """
        gg_api.get("/incidents/secrets/77").respond(200, json={"id": 77})

        await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})
        await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        # Only the dispatch path caches (per server instance, meaning
        # process-wide in production). The scope-filtered tool list cached here
        # is shared by all tenants of the process; per-call scope enforcement
        # is delegated to the GitGuardian API rejecting tokens that lack the
        # scope.
        scope_fetches = [call for call in gg_api.calls if call.request.url.path == "/v1/api_tokens/self"]
        assert len(scope_fetches) == 1

    async def test_explicit_tools_list_refetches_scopes_every_time(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the stateless remote deployment
        WHEN tools/list is requested twice
        THEN each request re-resolves the token's scopes upstream
        """
        await list_tool_names(mcp_client)
        await list_tool_names(mcp_client)

        scope_fetches = [call for call in gg_api.calls if call.request.url.path == "/v1/api_tokens/self"]
        assert len(scope_fetches) == 2


class TestAuthenticatedUserInfo:
    async def test_get_authenticated_user_info_reports_proxy_mode_and_scopes(self, mcp_client, mock_token_scopes):
        """
        GIVEN the hosted server in OAuth proxy mode
        WHEN get_authenticated_user_info is called
        THEN it returns the token info, the OAUTH_PROXY mode marker, and the scopes
        """
        mock_token_scopes(scopes=["scan", "incidents:read"])

        result = await call_tool(mcp_client, "get_authenticated_user_info")
        output = tool_output(result)

        assert output["authentication_mode"] == "OAUTH_PROXY"
        assert set(output["available_scopes"]) == {"scan", "incidents:read"}
        assert output["token_info"]["scopes"] == ["scan", "incidents:read"]


class TestExpiredTokenOnToolsList:
    async def test_rejected_token_on_scope_fetch_surfaces_as_json_rpc_error(self, mcp_client, gg_api):
        """
        GIVEN a token the GitGuardian API rejects with 401
        WHEN tools/list triggers the scope fetch
        THEN the request fails as a JSON-RPC error mentioning the downstream 401
        """
        gg_api.get("/api_tokens/self").respond(401, json={"detail": "Invalid API key."})

        response = await rpc(mcp_client, "tools/list")

        # TODO(SI-3891): the scope-filtering middleware raises outside the
        # DownstreamUnauthorized middleware, so the response stays HTTP 200 and
        # carries no WWW-Authenticate header; spec-abiding clients will not
        # re-run the OAuth flow on an expired token discovered here.
        assert response.status_code == 200
        assert "www-authenticate" not in response.headers
        body = response.json()
        assert "error" in body
        assert "401" in body["error"]["message"]


async def test_health_endpoint_requires_no_auth(mcp_client, gg_api):
    """
    GIVEN the remote server
    WHEN the load balancer probes /health without credentials
    THEN it answers 200 OK without contacting the GitGuardian API
    """
    response = await mcp_client.get("/health")

    assert response.status_code == 200
    assert response.text == "OK"
    assert not gg_api.calls
