"""Capture a real Sentry transaction for the MCP scrubbing integration test."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import sentry_sdk
from gg_api_core.sentry_integration import init_sentry
from gg_api_core.tools.scan_secret import ScanSecretsParams
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from sentry_sdk.envelope import Envelope
from sentry_sdk.transport import Transport

RAW_DOCUMENT = "AKIAIOSFODNN7EXAMPLE password = 'unrecognized-secret-format'"


class _CapturingTransport(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.envelopes: list[Envelope] = []

    def capture_envelope(self, envelope: Envelope) -> None:
        """Store an outgoing envelope instead of sending it over the network."""
        self.envelopes.append(envelope)


async def _call_scan_tool(server: FastMCP) -> None:
    async with create_connected_server_and_client_session(server) as session:
        await session.call_tool(
            "scan_secrets",
            {
                "documents": [
                    {
                        "document": RAW_DOCUMENT,
                        "filename": "settings.py",
                    }
                ]
            },
        )


def _transaction_from(transport: _CapturingTransport) -> dict[str, Any]:
    for envelope in transport.envelopes:
        for item in envelope.items:
            if transaction := item.get_transaction_event():
                return transaction
    raise AssertionError("Sentry did not emit a transaction")


def main(output_path: Path) -> None:
    """Run two MCP tools and write the captured Sentry transaction as JSON."""
    assert init_sentry() is True
    sentry_client = sentry_sdk.get_client()
    assert sentry_client.options["send_default_pii"] is False
    assert sentry_client.options["traces_sample_rate"] == 1.0

    transport = _CapturingTransport()
    sentry_client.transport = transport

    server = FastMCP("sentry-scrubbing-test")

    @server.tool()
    async def scan_secrets(params: ScanSecretsParams) -> str:
        """Accept scan parameters without making an API request."""
        return str(len(params.documents))

    with sentry_sdk.start_transaction(name="mcp-scrubbing-test"):
        asyncio.run(_call_scan_tool(server))

    sentry_sdk.flush()
    output_path.write_text(json.dumps(_transaction_from(transport)))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
