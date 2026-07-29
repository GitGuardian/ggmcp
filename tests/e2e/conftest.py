"""Fixtures for the remote MCP e2e suite (pure helpers live in harness.py).

Builds the production ASGI app with the same ``build_server`` and
``build_http_app`` used by ``gg_mcp_server.http_app`` (OAuth-proxy auth,
StreamableHTTP transport in stateless JSON mode) and drives it with raw
JSON-RPC 2.0 requests over an in-process httpx client.

Only the outbound GitGuardian API is faked, with respx (which patches httpx's
real AsyncHTTPTransport but not the ASGITransport used to reach the app). So
each test exercises the full production path:

    JSON-RPC over HTTP -> auth middleware -> FastMCP -> scope filtering
    -> tool -> GitGuardianClient -> (respx-mocked) GitGuardian API

Tests assert on the two boundaries only: the JSON-RPC response returned to the
MCP client, and the HTTP requests sent to the GitGuardian API.
"""

import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from gg_mcp_server.server import build_http_app, build_server

from tests.e2e.harness import GG_API_URL, MCP_BASE_URL, TEST_MEMBER_ID, token_info


@pytest.fixture
def remote_env(monkeypatch):
    """Environment of the hosted multi-tenant deployment (OAuth proxy mode)."""
    monkeypatch.setenv("MULTI_TENANCY_ENABLED", "true")
    # The presence of MCP_PORT marks the server as HTTP-transport: it gates
    # multi-tenant token extraction and the hosted-server behavior of tools
    # like find_current_source_id.
    monkeypatch.setenv("MCP_PORT", "8000")
    monkeypatch.setenv("MCP_OAUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("MCP_BASE_URL", MCP_BASE_URL)
    monkeypatch.setenv("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")
    monkeypatch.setenv("ENABLE_LOCAL_OAUTH", "false")
    monkeypatch.delenv("GITGUARDIAN_API_URL", raising=False)
    monkeypatch.delenv("GITGUARDIAN_PERSONAL_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
    monkeypatch.delenv("GITGUARDIAN_SCOPES", raising=False)
    monkeypatch.delenv("GITGUARDIAN_REQUESTED_SCOPES", raising=False)


@asynccontextmanager
async def _run_lifespan(app):
    """Run the app lifespan in a dedicated task.

    The StreamableHTTP session manager opens an anyio task group in the
    lifespan; anyio requires it to be entered and exited from the same task,
    but pytest-asyncio runs fixture setup and teardown in different tasks.
    """
    started = asyncio.Event()
    stop = asyncio.Event()

    async def holder() -> None:
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(holder())
    started_wait = asyncio.create_task(started.wait())
    done, _ = await asyncio.wait({task, started_wait}, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        # Startup failed: surface the exception instead of hanging on started.
        started_wait.cancel()
        task.result()
        raise RuntimeError("app lifespan exited before signaling startup")
    try:
        yield
    finally:
        stop.set()
        await task


@pytest.fixture
async def remote_app(remote_env, gg_api):
    """The production ASGI app, with its lifespan running.

    Depends on gg_api so the outbound mock guards the app's whole lifetime,
    startup included: any lifespan fetch against the real API fails loudly.
    """
    app = build_http_app(build_server())
    async with _run_lifespan(app):
        yield app


@pytest.fixture
async def mcp_client(remote_app):
    """An httpx client playing the role of the remote MCP client."""
    transport = httpx.ASGITransport(app=remote_app)
    async with httpx.AsyncClient(transport=transport, base_url=MCP_BASE_URL) as client:
        yield client


@pytest.fixture
def no_retry_delay(monkeypatch):
    """Make retry tests instant by patching asyncio.sleep to yield without waiting.

    The client awaits ``asyncio.sleep`` directly, so this patches the asyncio
    module attribute: every ``asyncio.sleep`` in the process is affected for
    the duration of the test, not just the client's backoff.
    """
    real_sleep = asyncio.sleep

    async def instant(_delay):
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", instant)


@pytest.fixture
def gg_api():
    """Mock of the GitGuardian API; unmocked outbound calls raise."""
    with respx.mock(base_url=GG_API_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
def mock_token_scopes(gg_api):
    """Register GET /api_tokens/self; returns a re-arm callable for custom scopes."""

    def _mock(scopes: list[str] | None = None, member_id: int | None = TEST_MEMBER_ID) -> respx.Route:
        return gg_api.get("/api_tokens/self").respond(200, json=token_info(scopes, member_id))

    _mock()
    return _mock
