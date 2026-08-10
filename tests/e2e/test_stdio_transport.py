"""Exercise the installed stdio entrypoint through a real MCP client process.

FastMCP owns the generic subprocess and JSON-RPC mechanics. This test covers
only GitGuardian behavior: the installed entrypoint starts, authenticates with
the environment PAT, calls the upstream API, and does not leak the token to
stderr.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator, override

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.e2e.harness import token_info

STDIO_PAT = "stdio-subprocess-pat"
READ_TIMEOUT = 5

INCIDENT: dict[str, Any] = {"id": 77, "status": "TRIGGERED"}

# The local fake serves the paths a localhost GITGUARDIAN_URL derives to.
API_PREFIX = "/exposed/v1"


class _FakeGitGuardianApi(BaseHTTPRequestHandler):
    payloads: dict[str, dict[str, Any]] = {
        f"{API_PREFIX}/api_tokens/self": token_info(),
        f"{API_PREFIX}/incidents/secrets/77": INCIDENT,
    }
    requests: list[dict[str, str | None]] = []

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        type(self).requests.append(
            {
                "path": path,
                "authorization": self.headers.get("Authorization"),
                "user_agent": self.headers.get("User-Agent"),
                "privacy_mode": self.headers.get("X-Privacy-Mode"),
            }
        )
        body = self.payloads.get(path)
        if body is None:
            self.send_error(404)
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @override
    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def fake_gg_api(socket_enabled: None) -> Iterator[ThreadingHTTPServer]:
    """Serve deterministic GitGuardian responses to the real child process."""
    _FakeGitGuardianApi.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGitGuardianApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=READ_TIMEOUT)
        assert not thread.is_alive()


async def test_installed_stdio_entrypoint_serves_gitguardian_tools(
    fake_gg_api: ThreadingHTTPServer,
    tmp_path: Path,
) -> None:
    """
    GIVEN the installed gg-mcp-server entrypoint, an environment PAT, and a
          local fake GitGuardian API
    WHEN a real MCP client calls get_incident over stdio
    THEN the incident is returned, every upstream request carries the expected
         headers, and the PAT is not logged
    """
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    stderr_log = tmp_path / "stdio-stderr.log"

    env = {
        "BROWSER": "/usr/bin/false",
        "ENABLE_LOCAL_OAUTH": "false",
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": STDIO_PAT,
        "GITGUARDIAN_URL": f"http://127.0.0.1:{fake_gg_api.server_address[1]}",
        "HOME": str(isolated_home),
        "LANG": "C.UTF-8",
        "LOG_FORMAT": "json",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
    }
    entrypoint = Path(sys.executable).with_name("gg-mcp-server")
    transport = StdioTransport(
        command=str(entrypoint),
        args=[],
        env=env,
        keep_alive=False,
        log_file=stderr_log,
    )

    async with Client(transport) as client:
        result = await client.call_tool(
            "get_incident",
            {"params": {"incident_id": 77}},
        )

    assert result.structured_content == {"incident": INCIDENT}

    api_requests = _FakeGitGuardianApi.requests
    assert [request["path"] for request in api_requests] == [
        f"{API_PREFIX}/api_tokens/self",  # startup scope discovery
        f"{API_PREFIX}/api_tokens/self",  # caller identity for log enrichment
        f"{API_PREFIX}/incidents/secrets/77",
    ]
    assert {request["authorization"] for request in api_requests} == {f"Token {STDIO_PAT}"}
    assert {request["privacy_mode"] for request in api_requests} == {"true"}
    assert all(
        request["user_agent"] is not None and "(transport=stdio)" in request["user_agent"] for request in api_requests
    )

    assert STDIO_PAT not in stderr_log.read_text()
