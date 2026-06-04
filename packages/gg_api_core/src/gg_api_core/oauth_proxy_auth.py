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
from collections.abc import Callable
from contextvars import ContextVar
from urllib.parse import urlencode

import httpx
from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)


_downstream_unauthorized: ContextVar[bool] = ContextVar("downstream_unauthorized", default=False)


def mark_downstream_unauthorized() -> None:
    """Signal that the downstream GG API rejected the current request as unauthorized.

    Call this from anywhere inside the request task (typically a FastMCP
    middleware catching :class:`DownstreamUnauthorizedError`). The outgoing
    response will then carry HTTP 401 instead of the JSON-RPC error envelope
    FastMCP would otherwise serialize, letting the MCP client re-run the
    OAuth flow.
    """
    _downstream_unauthorized.set(True)


class PassThroughTokenVerifier(TokenVerifier):
    """Token verifier that trusts the bearer token without contacting the IdP.

    Used by MCP modes where the GG API is the source of truth: the verifier
    accepts the token so it lands in the request scope, and downstream calls
    fail with a real 401 if the token is invalid.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        return AccessToken(token=token, client_id="unknown", scopes=[])


class TranslateDownstreamUnauthorizedMiddleware:
    """Convert flagged tool responses into HTTP 401.

    Reads the request-scoped flag set by :func:`mark_downstream_unauthorized`
    and rewrites the outgoing status to 401 when set. Pairs with
    :class:`AdvertiseAuthorizationServerMetadataMiddleware` which then
    ensures ``WWW-Authenticate`` is present.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        token = _downstream_unauthorized.set(False)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and _downstream_unauthorized.get():
                message["status"] = 401
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _downstream_unauthorized.reset(token)


class AdvertiseAuthorizationServerMetadataMiddleware:
    """Ensure 401 responses advertise both ``resource_metadata`` and ``as_metadata``.

    * **Augment branch.** When FastMCP's auth backend already emitted a 401
      with ``WWW-Authenticate: Bearer resource_metadata="..."``, append
      ``, as_metadata="..."`` so Claude.ai (which does not follow RFC 9728
      ``authorization_servers``, see
      https://github.com/anthropics/claude-ai-mcp/issues/82) can locate the
      AS metadata directly.
    * **Synthesize branch.** When a 401 carries no ``WWW-Authenticate`` at
      all (the case after :class:`TranslateDownstreamUnauthorizedMiddleware`
      flips a 200 into a 401), build one with **both** ``resource_metadata``
      (so spec-compliant clients can discover via the standard chain) and
      ``as_metadata`` (so Claude.ai can shortcut).

    ``resource_metadata_url`` is resolved lazily on each request because
    FastMCP constructs the middleware before calling ``set_mcp_path()`` on
    the auth provider — the resource URL isn't known at middleware
    construction time.
    """

    def __init__(
        self,
        app: ASGIApp,
        as_metadata_url: str,
        resource_metadata_url_provider: Callable[[], str | None] | None = None,
    ):
        self.app = app
        self._as_param = f'as_metadata="{as_metadata_url}"'
        self._append_suffix = f", {self._as_param}".encode()
        self._resource_metadata_url_provider = resource_metadata_url_provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and message.get("status") == 401:
                headers = list(message.get("headers", []))
                for i, (name, value) in enumerate(headers):
                    if name.lower() == b"www-authenticate":
                        headers[i] = (name, value + self._append_suffix)
                        break
                else:
                    headers.append((b"www-authenticate", self._build_synth_header()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _build_synth_header(self) -> bytes:
        parts: list[str] = []
        if self._resource_metadata_url_provider is not None:
            rm_url = self._resource_metadata_url_provider()
            if rm_url:
                parts.append(f'resource_metadata="{rm_url}"')
        parts.append(self._as_param)
        return f"Bearer {', '.join(parts)}".encode()


class GitGuardianOAuthThinProxy(PassThroughTokenVerifier):
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
        advertised_scopes: list[str] | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.gg_authorize_url = gg_authorize_url
        self.gg_token_url = gg_token_url
        self.gg_register_url = gg_register_url
        self.gg_api_url = gg_api_url.rstrip("/")
        self.gg_client_id = gg_client_id
        self._advertised_scopes = advertised_scopes

    @property
    def scopes_supported(self) -> list[str]:
        return self._advertised_scopes or ["scan"]

    def get_middleware(self) -> list:
        """Add downstream-401 handling and WWW-Authenticate advertising.

        Order matters. ``TranslateDownstreamUnauthorizedMiddleware`` runs
        first so a flagged response becomes a 401; then
        ``AdvertiseAuthorizationServerMetadataMiddleware`` enriches the
        resulting ``WWW-Authenticate`` header with ``resource_metadata``
        and ``as_metadata`` parameters.
        """
        middleware = super().get_middleware()
        middleware.append(Middleware(TranslateDownstreamUnauthorizedMiddleware))
        base = str(self.base_url).rstrip("/") if self.base_url else ""
        if base:
            middleware.append(
                Middleware(
                    AdvertiseAuthorizationServerMetadataMiddleware,
                    as_metadata_url=f"{base}/.well-known/oauth-authorization-server",
                    resource_metadata_url_provider=self._build_resource_metadata_url,
                )
            )
        return middleware

    def _build_resource_metadata_url(self) -> str | None:
        """Resolve the RFC 9728 protected-resource metadata URL.

        Called lazily per request because ``set_mcp_path()`` runs after
        ``get_middleware()`` during FastMCP's app construction — at
        middleware-construction time ``self._resource_url`` is still ``None``.
        """
        from mcp.server.auth.routes import build_resource_metadata_url

        resource_url = getattr(self, "_resource_url", None)
        if not resource_url:
            return None
        return str(build_resource_metadata_url(resource_url))

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
                # RFC 8414 §3.3: the issuer MUST equal the value used to build
                # the well-known URL (this server's base, no trailing slash).
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "registration_endpoint": f"{base}/register",
                "scopes_supported": self.scopes_supported,
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                # Mirror what the GG backend actually accepts at /register and
                # /token (its DCR serializer only permits "none" and
                # "client_secret_post"). Advertising client_secret_basic would
                # let a confidential client pick a method registration rejects.
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post",
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
                # Must match the AS metadata issuer exactly (no trailing slash).
                "authorization_servers": [base],
                "scopes_supported": self.scopes_supported,
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

        Passes through all query params, including the client's own
        ``client_id`` so RFC 7591 (DCR) clients reach the GG backend with
        their registered identity. Falls back to ``self.gg_client_id`` only
        when the request omits ``client_id``.
        """
        params = dict(request.query_params)
        params.setdefault("client_id", self.gg_client_id)

        # Add GG-specific params. "oauth2_login" is the canonical auth_mode the
        # dashboard expects; "ggshield_login" is its still-accepted legacy alias.
        params.setdefault("auth_mode", "oauth2_login")
        params.setdefault("utm_source", "mcp")
        params.setdefault("utm_medium", "oauth_proxy")

        separator = "&" if "?" in self.gg_authorize_url else "?"
        url = f"{self.gg_authorize_url}{separator}{urlencode(params)}"
        return RedirectResponse(url=url, status_code=302)

    async def _handle_token(self, request: Request) -> JSONResponse:
        """Proxy token exchange to GG dashboard, transforming the response.

        Forwards the request to the GG token endpoint, passing through the
        client's own ``client_id`` (and ``client_secret`` when present) so
        RFC 7591 (DCR) clients can complete the code exchange with their
        registered identity. Transforms ``{key: "..."}`` →
        ``{access_token: "..."}`` in the response.
        """
        body = await request.body()
        form_data = dict(request.query_params)

        # Parse form body
        for pair in body.decode().split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                from urllib.parse import unquote_plus

                form_data[k] = unquote_plus(v)

        # Fall back to the configured client only when none was sent
        form_data.setdefault("client_id", self.gg_client_id)

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
    advertised_scopes: list[str] | None = None,
) -> GitGuardianOAuthThinProxy:
    """Create a thin OAuth proxy that routes auth to the GG dashboard.

    Args:
        base_url: Public URL of this MCP server.
        gg_url: GG dashboard URL.
        gg_api_url: GG API URL. If None, derived from gg_url.
        gg_client_id: OAuth client ID registered on the GG dashboard.
        advertised_scopes: Scopes advertised in AS / protected-resource
            metadata so DCR clients (Claude.ai, Cursor, …) request them
            at registration / authorize time. Defaults to ``["scan"]``.
    """
    if gg_api_url is None:
        from gg_api_core.urls import derive_public_api_url

        gg_api_url = derive_public_api_url(gg_url)  # e.g. https://api.gitguardian.com/v1

    return GitGuardianOAuthThinProxy(
        gg_authorize_url=f"{gg_url}/auth/login",
        gg_token_url=f"{gg_api_url}/oauth/token",
        gg_register_url=f"{gg_api_url}/oauth/register",
        gg_api_url=gg_api_url,
        advertised_scopes=advertised_scopes,
        gg_client_id=gg_client_id,
        base_url=base_url,
    )
