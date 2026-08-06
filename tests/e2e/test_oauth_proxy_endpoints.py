"""OAuth proxy surface of the remote MCP server.

Claude.ai and other DCR clients authenticate through these same-origin
endpoints; if discovery metadata, the authorize redirect, or the token
exchange transformation regress, every remote user loses access.
"""

from urllib.parse import parse_qs, urlparse

from pytest_voluptuous import S, Unordered

from tests.e2e.harness import EXPECTED_SCOPES, MCP_BASE_URL, sent_body


class TestDiscoveryMetadata:
    async def test_authorization_server_metadata_points_to_same_origin_endpoints(self, mcp_client):
        """
        GIVEN the hosted server
        WHEN a client fetches RFC 8414 authorization-server metadata
        THEN issuer and endpoints are all rooted at the server's own base URL
        """
        response = await mcp_client.get("/.well-known/oauth-authorization-server")

        assert response.status_code == 200
        metadata = response.json()
        assert metadata >= S(
            {
                "issuer": MCP_BASE_URL,
                "authorization_endpoint": f"{MCP_BASE_URL}/authorize",
                "token_endpoint": f"{MCP_BASE_URL}/token",
                "registration_endpoint": f"{MCP_BASE_URL}/register",
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                "scopes_supported": Unordered(EXPECTED_SCOPES),
            }
        )

    async def test_protected_resource_metadata_advertises_this_authorization_server(self, mcp_client):
        """
        GIVEN the hosted server
        WHEN a client fetches RFC 9728 protected-resource metadata
        THEN the MCP endpoint is the resource and the server itself is the AS
        """
        response = await mcp_client.get("/.well-known/oauth-protected-resource/mcp")

        assert response.status_code == 200
        metadata = response.json()
        assert metadata >= S(
            {
                "resource": f"{MCP_BASE_URL}/mcp",
                "authorization_servers": [MCP_BASE_URL],
                "bearer_methods_supported": ["header"],
                "scopes_supported": Unordered(EXPECTED_SCOPES),
            }
        )


class TestAuthorizeRedirect:
    async def test_authorize_redirects_to_dashboard_login_with_client_params(self, mcp_client):
        """
        GIVEN a DCR client starting the OAuth flow
        WHEN it hits /authorize with its own client_id and PKCE params
        THEN it is redirected to the GitGuardian dashboard login, params intact,
             with the GG-specific auth_mode added
        """
        response = await mcp_client.get(
            "/authorize",
            params={
                "client_id": "my-dcr-client",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": "abc123",
                "code_challenge_method": "S256",
                "response_type": "code",
                "scope": "scan incidents:read",
                "state": "csrf-state-123",
            },
        )

        assert response.status_code == 302
        location = urlparse(response.headers["location"])
        assert location.scheme == "https"
        assert location.netloc == "dashboard.gitguardian.com"
        assert location.path == "/auth/login"
        query = parse_qs(location.query)
        assert query["client_id"] == ["my-dcr-client"]
        assert query["redirect_uri"] == ["https://claude.ai/api/mcp/auth_callback"]
        assert query["code_challenge"] == ["abc123"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["scan incidents:read"]
        assert query["state"] == ["csrf-state-123"]
        assert query["auth_mode"] == ["oauth2_login"]

    async def test_authorize_falls_back_to_the_ggshield_client_id(self, mcp_client):
        """
        GIVEN a client that omits client_id
        WHEN it hits /authorize
        THEN the redirect carries the default ggshield_oauth client_id
        """
        response = await mcp_client.get("/authorize", params={"response_type": "code"})

        assert response.status_code == 302
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["client_id"] == ["ggshield_oauth"]


class TestDynamicClientRegistration:
    async def test_registration_json_and_response_are_proxied_semantically_unchanged(self, mcp_client, gg_api):
        """
        GIVEN an MCP client dynamically registering its OAuth callback
        WHEN it posts the registration document to the local proxy
        THEN the same JSON document reaches GitGuardian and its response is relayed
        """
        registration = {
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        }
        registered_client = {
            **registration,
            "client_id": "registered-client-id",
        }
        upstream = gg_api.post("/oauth/register").respond(201, json=registered_client)

        response = await mcp_client.post("/register", json=registration)

        assert response.status_code == 201
        assert response.json() == registered_client
        assert upstream.calls.last.request.headers["Content-Type"] == "application/json"
        assert sent_body(upstream) == registration


class TestTokenExchange:
    async def test_token_exchange_transforms_gitguardian_key_into_oauth_access_token(self, mcp_client, gg_api):
        """
        GIVEN GitGuardian's token endpoint returning its non-standard {key: ...}
        WHEN the client exchanges its authorization code at /token
        THEN the upstream call carries the code plus the proxy's token name and
             lifetime, and the response is reshaped to standard OAuth fields
        """
        upstream = gg_api.post("/oauth/token").respond(
            200, json={"key": "gg-pat-from-exchange", "scope": ["scan", "incidents:read"]}
        )

        response = await mcp_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "auth-code-1",
                "client_id": "my-dcr-client",
                "code_verifier": "verifier",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            },
        )

        assert response.status_code == 200
        assert response.json() == {
            "access_token": "gg-pat-from-exchange",
            "token_type": "Bearer",
            "scope": "scan incidents:read",
        }
        sent = parse_qs(upstream.calls.last.request.content.decode())
        assert sent["grant_type"] == ["authorization_code"]
        assert sent["code"] == ["auth-code-1"]
        assert sent["client_id"] == ["my-dcr-client"]
        assert sent["code_verifier"] == ["verifier"]
        assert sent["redirect_uri"] == ["https://claude.ai/api/mcp/auth_callback"]
        assert sent["name"] == ["MCP server token (OAuth Proxy)"]
        assert sent["lifetime"] == ["90"]

    async def test_confidential_client_secret_is_forwarded_in_the_form_body(self, mcp_client, gg_api):
        """
        GIVEN a registered confidential client using client_secret_post
        WHEN it exchanges an authorization code
        THEN its client secret and redirect binding reach GitGuardian unchanged
        """
        upstream = gg_api.post("/oauth/token").respond(200, json={"key": "confidential-client-pat"})

        response = await mcp_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "confidential-auth-code",
                "client_id": "confidential-client",
                "client_secret": "test-client-secret",
                "redirect_uri": "https://client.example.test/oauth/callback",
            },
        )

        assert response.status_code == 200
        assert response.json()["access_token"] == "confidential-client-pat"
        sent = parse_qs(upstream.calls.last.request.content.decode())
        assert sent["grant_type"] == ["authorization_code"]
        assert sent["code"] == ["confidential-auth-code"]
        assert sent["client_id"] == ["confidential-client"]
        assert sent["client_secret"] == ["test-client-secret"]
        assert sent["redirect_uri"] == ["https://client.example.test/oauth/callback"]

    async def test_token_exchange_passes_upstream_errors_through(self, mcp_client, gg_api):
        """
        GIVEN GitGuardian rejecting the code exchange
        WHEN the client hits /token
        THEN the upstream error body and status are relayed untransformed
        """
        gg_api.post("/oauth/token").respond(400, json={"error": "invalid_grant"})

        response = await mcp_client.post("/token", data={"grant_type": "authorization_code", "code": "bad"})

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
