"""Thin OAuth proxy for GitGuardian MCP Server.

Routes same-origin OAuth endpoints to the GG dashboard to work around
Claude.ai issue #82 (requires OAuth endpoints on same origin as MCP server).

Architecture: single OAuth loop, no JWT issuance, no server-side token storage.
The MCP client gets the real GG PAT directly and sends it as Bearer token.

    MCP Client ──Bearer PAT──► MCP Server ──PAT──► GG API
                                    │
                    /authorize ─────┼──► 302 to GG dashboard /auth/login
                    /token ─────────┼──► proxy to GG API /oauth/token
                    /register ──────┼──► proxy to GG API /oauth/register
"""

import logging
import os
from urllib.parse import urlencode

import httpx
from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)


class GitGuardianOAuthThinProxy(TokenVerifier):
    """Thin OAuth proxy that routes auth requests to the GG dashboard.

    Serves same-origin OAuth endpoints so MCP clients that require
    same-origin OAuth (Claude.ai as per https://github.com/anthropics/claude-ai-mcp/issues/82) can authenticate
    with the GG dashboard. The client receives the real GG PAT — no intermediate JWTs or storage.
    """

    def __init__(
        self,
        gg_authorize_url: str,
        gg_token_url: str,
        gg_register_url: str,
        gg_api_url: str,
        gg_client_id: str = "ggshield_oauth",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.gg_authorize_url = gg_authorize_url
        self.gg_token_url = gg_token_url
        self.gg_register_url = gg_register_url
        self.gg_api_url = gg_api_url.rstrip("/")
        self.gg_client_id = gg_client_id

    # TODO(TIM): Should we implement this method or let actual calls fail with 401 ?
    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a GG PAT by calling /api_tokens/self."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.gg_api_url}/api_tokens/self",
                    headers={"Authorization": f"Token {token}"},
                )

            if response.status_code != 200:
                logger.warning(f"Token verification failed: HTTP {response.status_code}")
                return None

            token_info = response.json()
            scopes = token_info.get("scopes", [])

            return AccessToken(
                token=token,
                client_id=token_info.get("id", "unknown"),
                scopes=scopes,
            )
        except Exception:
            logger.exception("Error verifying upstream token")
            return None

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Return OAuth proxy routes alongside discovery metadata."""
        self.set_mcp_path(mcp_path)

        return [
            Route(
                f"/.well-known/oauth-protected-resource{mcp_path or ''}",
                self._handle_resource_metadata,
                methods=["GET"],
            ),
            # The following routes are served to workaround Claude.ai issue regarding
            # Protected Resource metadata (RFC 9728) : https://github.com/anthropics/claude-ai-mcp/issues/82
            Route(
                "/.well-known/oauth-authorization-server",
                self._handle_authorization_server_metadata,
                methods=["GET"],
            ),
            Route("/authorize", self._handle_authorize, methods=["GET"]),
            Route("/token", self._handle_token, methods=["POST"]),
            Route("/register", self._handle_register, methods=["POST"]),
        ]

    async def _handle_authorization_server_metadata(self, request: Request) -> JSONResponse:
        """Serve OAuth Authorization Server metadata (RFC 8414)."""
        base = str(self.base_url).rstrip("/")
        return JSONResponse(
            {
                "issuer": f"{base}/",
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "registration_endpoint": f"{base}/register",
                "scopes_supported": self.scopes_supported or ["scan"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "client_secret_basic",
                ],
                "code_challenge_methods_supported": ["S256"],
            },
            headers={"Cache-Control": "public, max-age=3600"},
        )

    async def _handle_resource_metadata(self, request: Request) -> JSONResponse:
        """Serve OAuth Protected Resource metadata (RFC 9728)."""
        base = str(self.base_url).rstrip("/")
        return JSONResponse(
            {
                "resource": str(self._resource_url),
                "authorization_servers": [f"{base}/"],
                "scopes_supported": self.scopes_supported or ["scan"],
                "bearer_methods_supported": ["header"],
            },
            headers={"Cache-Control": "public, max-age=3600"},
        )

    async def _handle_register(self, request: Request) -> JSONResponse:
        """Proxy Dynamic Client Registration (DCR) to the GG dashboard."""
        body = await request.body()

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                self.gg_register_url,
                content=body,
                headers={"Content-Type": "application/json"},
            )

        return JSONResponse(
            response.json(),
            status_code=response.status_code,
        )

    async def _handle_authorize(self, request: Request) -> RedirectResponse:
        """Redirect to GG dashboard authorization endpoint.

        Passes through all query params, replacing client_id with ggshield_oauth.
        """
        params = dict(request.query_params)
        params["client_id"] = self.gg_client_id

        # Add GG-specific params
        params.setdefault("auth_mode", "ggshield_login")
        params.setdefault("utm_source", "mcp")
        params.setdefault("utm_medium", "oauth_proxy")

        separator = "&" if "?" in self.gg_authorize_url else "?"
        url = f"{self.gg_authorize_url}{separator}{urlencode(params)}"
        return RedirectResponse(url=url, status_code=302)

    async def _handle_token(self, request: Request) -> JSONResponse:
        """Proxy token exchange to GG dashboard, transforming the response.

        Forwards the request to the GG token endpoint, replacing client_id,
        and transforms {key: "..."} → {access_token: "..."} in the response.
        """
        body = await request.body()
        form_data = dict(request.query_params)

        # Parse form body
        for pair in body.decode().split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                from urllib.parse import unquote_plus

                form_data[k] = unquote_plus(v)

        # Replace client_id with the real GG client
        form_data["client_id"] = self.gg_client_id

        # Add token name
        token_name = os.environ.get("MCP_OAUTH_TOKEN_NAME", "MCP server token (OAuth Proxy)")
        form_data.setdefault("name", token_name)

        # Add token lifetime
        token_lifetime = os.environ.get("GITGUARDIAN_TOKEN_LIFETIME")
        if token_lifetime and token_lifetime.lower() != "never":
            form_data.setdefault("lifetime", token_lifetime)

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                self.gg_token_url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if response.status_code != 200:
            return JSONResponse(
                response.json()
                if response.headers.get("content-type", "").startswith("application/json")
                else {"error": response.text},
                status_code=response.status_code,
            )

        token_data = response.json()

        # Transform GG's non-standard response to OAuth standard
        access_token = token_data.get("access_token") or token_data.get("key")
        if not access_token:
            return JSONResponse(
                {"error": "server_error", "error_description": "No access token in upstream response"},
                status_code=500,
            )

        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "scope": " ".join(token_data.get("scope", ["scan"]))
                if isinstance(token_data.get("scope"), list)
                else token_data.get("scope", "scan"),
            }
        )


def create_oauth_proxy(
    base_url: str,
    gg_url: str = "https://dashboard.gitguardian.com",
    gg_api_url: str | None = None,
    gg_client_id: str = "ggshield_oauth",
) -> GitGuardianOAuthThinProxy:
    """Create a thin OAuth proxy that routes auth to the GG dashboard.

    Args:
        base_url: Public URL of this MCP server.
        gg_url: GG dashboard URL.
        gg_api_url: GG API URL. If None, derived from gg_url.
        gg_client_id: OAuth client ID registered on the GG dashboard.
    """
    if gg_api_url is None:
        from gg_api_core.client import GitGuardianClient

        temp_client = GitGuardianClient.__new__(GitGuardianClient)
        temp_client._init_urls(gg_url)
        gg_api_url = temp_client.public_api_url  # e.g. https://api.gitguardian.com/v1

    return GitGuardianOAuthThinProxy(
        gg_authorize_url=f"{gg_url}/auth/login",
        gg_token_url=f"{gg_api_url}/oauth/token",
        gg_register_url=f"{gg_api_url}/oauth/register",
        gg_api_url=gg_api_url,
        gg_client_id=gg_client_id,
        base_url=base_url,
    )
