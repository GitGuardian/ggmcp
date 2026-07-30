"""True end-to-end run of the stdio server: the real gg-mcp-server process,
raw JSON-RPC over its stdin/stdout, and a local fake GitGuardian API.

This is the one place the actual entrypoint, stdio framing, and stderr-only
logging are exercised; per-tool behavior lives in the in-process suites.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any, Iterator, cast, override

import pytest
from mcp.types import LATEST_PROTOCOL_VERSION

from tests.e2e.harness import EXPECTED_FULL_TOOL_CATALOG, token_info

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
def fake_gg_api() -> Iterator[ThreadingHTTPServer]:
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


class _StdioSession:
    """Line-delimited JSON-RPC over a child process's pipes."""

    def __init__(self, process: subprocess.Popen[str]):
        self.process = process
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        self.stdin: IO[str] = process.stdin
        self.stdout: IO[str] = process.stdout
        self.stderr: IO[str] = process.stderr
        self.stdout_lines: list[str] = []
        self.stderr_lines: list[str] = []
        self.notifications: list[dict[str, Any]] = []
        self._readers_finished = False
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._stdout_reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_reader.start()
        self._stderr_reader.start()

    def _read_stdout(self) -> None:
        try:
            for line in self.stdout:
                self._queue.put(line)
        finally:
            self._queue.put(None)

    def _read_stderr(self) -> None:
        for line in self.stderr:
            self.stderr_lines.append(line)

    def send(self, message: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(message) + "\n")
        self.stdin.flush()

    def receive(self, timeout: float = READ_TIMEOUT) -> dict[str, Any]:
        try:
            line = self._queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise AssertionError(
                f"Timed out waiting for stdio response; process={self.process.poll()}, stderr={self.stderr_lines[-5:]}"
            ) from exc
        if line is None:
            raise AssertionError(
                f"stdio process exited before responding; code={self.process.poll()}, stderr={self.stderr_lines[-5:]}"
            )
        self.stdout_lines.append(line)
        message: object = json.loads(line)
        assert isinstance(message, dict), f"stdio emitted a non-object JSON-RPC frame: {message!r}"
        return cast(dict[str, Any], message)

    def request(
        self,
        request_id: int | str,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + READ_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"Timed out waiting for JSON-RPC id={request_id}")
            message = self.receive(timeout=remaining)
            if message.get("id") == request_id:
                assert message["jsonrpc"] == "2.0"
                return message
            if "id" in message:
                raise AssertionError(
                    f"Received out-of-order JSON-RPC response id={message['id']!r}; expected id={request_id}"
                )
            self.notifications.append(message)

    def close_input_and_wait(self) -> int:
        """Close stdin as a real client would and wait for a clean server exit."""
        if not self.stdin.closed:
            self.stdin.close()
        return_code = self.process.wait(timeout=READ_TIMEOUT)
        self._finish_readers()
        return return_code

    def _finish_readers(self) -> None:
        """Join pipe readers and collect every remaining stdout frame."""
        if self._readers_finished:
            return

        self._stdout_reader.join(timeout=READ_TIMEOUT)
        self._stderr_reader.join(timeout=READ_TIMEOUT)
        assert not self._stdout_reader.is_alive()
        assert not self._stderr_reader.is_alive()
        while True:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                break
            if line is not None:
                self.stdout_lines.append(line)
        self.stdout.close()
        self.stderr.close()
        self._readers_finished = True

    def cleanup(self) -> None:
        """Require a clean exit, using terminate/kill only to prevent leaked children."""
        forced_shutdown = False
        if self.process.poll() is None:
            if not self.stdin.closed:
                self.stdin.close()
            try:
                self.process.wait(timeout=READ_TIMEOUT)
            except subprocess.TimeoutExpired:
                forced_shutdown = True
                self.process.terminate()
                try:
                    self.process.wait(timeout=READ_TIMEOUT)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=READ_TIMEOUT)
        self._finish_readers()
        assert not forced_shutdown, "stdio server did not exit after EOF"
        assert self.process.returncode == 0, (
            f"stdio server exited with {self.process.returncode}; stderr={self.stderr_lines[-5:]}"
        )


@pytest.fixture
def stdio_session(fake_gg_api: ThreadingHTTPServer, tmp_path: Path) -> Iterator[_StdioSession]:
    """Launch the installed stdio entrypoint in an isolated child environment."""
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    isolation_sentinel = tmp_path / "isolation-active.json"
    sitecustomize_dir = tmp_path / "sitecustomize"
    sitecustomize_dir.mkdir()
    (sitecustomize_dir / "sitecustomize.py").write_text(
        "import json\n"
        "import socket\n"
        "import os\n"
        "import pathlib\n"
        "import webbrowser\n"
        "\n"
        "pathlib.Path.home = classmethod(lambda cls: pathlib.Path(os.environ['GGMCP_TEST_HOME']))\n"
        "\n"
        "def blocked_browser(*args, **kwargs):\n"
        "    raise AssertionError('stdio test child attempted to open a browser')\n"
        "\n"
        "webbrowser.open = blocked_browser\n"
        "webbrowser.open_new = blocked_browser\n"
        "webbrowser.open_new_tab = blocked_browser\n"
        "\n"
        "_original_connect = socket.socket.connect\n"
        "_original_connect_ex = socket.socket.connect_ex\n"
        "_original_getaddrinfo = socket.getaddrinfo\n"
        "_loopback_hosts = {'127.0.0.1', '::1', 'localhost'}\n"
        "\n"
        "def loopback_only_connect(sock, address):\n"
        "    if not isinstance(address, tuple) or address[0] not in _loopback_hosts:\n"
        "        raise AssertionError(f'stdio test child attempted a non-loopback connection: {address!r}')\n"
        "    return _original_connect(sock, address)\n"
        "\n"
        "def loopback_only_connect_ex(sock, address):\n"
        "    if not isinstance(address, tuple) or address[0] not in _loopback_hosts:\n"
        "        raise AssertionError(f'stdio test child attempted non-loopback connect_ex: {address!r}')\n"
        "    return _original_connect_ex(sock, address)\n"
        "\n"
        "def loopback_only_getaddrinfo(host, *args, **kwargs):\n"
        "    if host not in _loopback_hosts:\n"
        "        raise AssertionError(f'stdio test child attempted non-loopback DNS: {host!r}')\n"
        "    return _original_getaddrinfo(host, *args, **kwargs)\n"
        "\n"
        "socket.socket.connect = loopback_only_connect\n"
        "socket.socket.connect_ex = loopback_only_connect_ex\n"
        "socket.getaddrinfo = loopback_only_getaddrinfo\n"
        "\n"
        "pathlib.Path(os.environ['GGMCP_ISOLATION_SENTINEL']).write_text(json.dumps({\n"
        "    'browser_guard': webbrowser.open is blocked_browser,\n"
        "    'home': str(pathlib.Path.home()),\n"
        "    'socket_connect_guard': socket.socket.connect is loopback_only_connect,\n"
        "    'socket_connect_ex_guard': socket.socket.connect_ex is loopback_only_connect_ex,\n"
        "    'socket_dns_guard': socket.getaddrinfo is loopback_only_getaddrinfo,\n"
        "}))\n"
    )
    env = {
        "BROWSER": "/usr/bin/false",
        "ENABLE_LOCAL_OAUTH": "false",
        "GGMCP_ISOLATION_SENTINEL": str(isolation_sentinel),
        "GGMCP_TEST_HOME": str(isolated_home),
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": STDIO_PAT,
        "GITGUARDIAN_URL": f"http://127.0.0.1:{fake_gg_api.server_address[1]}",
        "LANG": "C.UTF-8",
        "LOG_FORMAT": "json",
        "NO_PROXY": "127.0.0.1,localhost",
        "PATH": os.defpath,
        "PYTHONPATH": str(sitecustomize_dir),
        "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
        "no_proxy": "127.0.0.1,localhost",
    }
    entrypoint = Path(sys.executable).with_name("gg-mcp-server")
    process = subprocess.Popen(
        [str(entrypoint)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    session = _StdioSession(process)
    try:
        sentinel_deadline = time.monotonic() + READ_TIMEOUT
        while not isolation_sentinel.exists() and process.poll() is None:
            if time.monotonic() >= sentinel_deadline:
                break
            time.sleep(0.01)
        assert isolation_sentinel.exists(), (
            f"stdio child did not activate its isolation guards; code={process.poll()}, "
            f"stderr={session.stderr_lines[-5:]}"
        )
        assert json.loads(isolation_sentinel.read_text()) == {
            "browser_guard": True,
            "home": str(isolated_home),
            "socket_connect_guard": True,
            "socket_connect_ex_guard": True,
            "socket_dns_guard": True,
        }
        yield session
    finally:
        session.cleanup()


def test_full_stdio_session_against_the_real_entrypoint(
    stdio_session: _StdioSession,
    fake_gg_api: ThreadingHTTPServer,
) -> None:
    """
    GIVEN the real gg-mcp-server process talking to a local fake GitGuardian API
    WHEN a client runs initialize, tools/list and a tools/call over its pipes
    THEN the whole session succeeds, the env token reaches the API, and stdout
         carries nothing but JSON-RPC frames
    """
    init = stdio_session.request(
        "initialize-1",
        "initialize",
        {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0"},
        },
    )
    assert init["jsonrpc"] == "2.0"
    assert init["id"] == "initialize-1"
    assert init["result"]["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "GitGuardian"
    assert "tools" in init["result"]["capabilities"]
    assert init["result"]["instructions"]
    stdio_session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    listed = stdio_session.request(2, "tools/list", {})
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert names == EXPECTED_FULL_TOOL_CATALOG

    called = stdio_session.request(
        3, "tools/call", {"name": "get_incident", "arguments": {"params": {"incident_id": 77}}}
    )
    assert called["result"]["isError"] is False
    assert called["result"]["structuredContent"] == {"incident": INCIDENT}
    assert json.loads(called["result"]["content"][0]["text"]) == {"incident": INCIDENT}

    # The env token, and only it, authenticated every upstream call, with the
    # stdio transport marker; the startup scope fetch happened server-side.
    api_requests = _FakeGitGuardianApi.requests
    assert [req["path"] for req in api_requests] == [
        f"{API_PREFIX}/api_tokens/self",
        f"{API_PREFIX}/incidents/secrets/77",
    ]
    assert {req["authorization"] for req in api_requests} == {f"Token {STDIO_PAT}"}
    assert {req["privacy_mode"] for req in api_requests} == {"true"}
    assert all(req["user_agent"] is not None and "(transport=stdio)" in req["user_agent"] for req in api_requests)

    assert stdio_session.close_input_and_wait() == 0
    assert STDIO_PAT not in "".join(stdio_session.stderr_lines)

    # Protocol purity: every stdout line must be a JSON-RPC frame; a single
    # stray print or stdout log line breaks every stdio client.
    assert stdio_session.stdout_lines
    for line in stdio_session.stdout_lines:
        assert json.loads(line).get("jsonrpc") == "2.0"


def test_failed_tool_call_returns_a_json_rpc_error_result(stdio_session: _StdioSession) -> None:
    """
    GIVEN an initialized real stdio server
    WHEN the client calls a tool that does not exist
    THEN the response is a correlated JSON-RPC tool error and the server exits cleanly
    """
    stdio_session.request(
        10,
        "initialize",
        {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0"},
        },
    )
    stdio_session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    failed = stdio_session.request(
        "missing-tool-call",
        "tools/call",
        {"name": "tool_that_does_not_exist", "arguments": {}},
    )

    assert failed["jsonrpc"] == "2.0"
    assert failed["id"] == "missing-tool-call"
    result = failed["result"]
    assert result["isError"] is True
    assert "tool_that_does_not_exist" in result["content"][0]["text"]
    assert stdio_session.close_input_and_wait() == 0
