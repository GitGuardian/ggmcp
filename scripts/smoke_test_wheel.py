"""Smoke-test an installed ``gg-mcp-server`` console script over MCP stdio."""

import argparse
import asyncio
import os
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def smoke_test_server(command: Path) -> None:
    """Initialize an installed server and verify its MCP identity."""
    environment = {**os.environ, "ENABLE_LOCAL_OAUTH": "false"}
    environment.pop("GITGUARDIAN_PERSONAL_ACCESS_TOKEN", None)

    server_parameters = StdioServerParameters(command=str(command), env=environment)

    async with asyncio.timeout(30):
        async with stdio_client(server_parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                initialization = await session.initialize()

    if initialization.serverInfo.name != "GitGuardian":
        raise RuntimeError(f"Unexpected MCP server name: {initialization.serverInfo.name}")


def main() -> None:
    """Parse the installed executable path and run the smoke test."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=Path, help="Path to the installed gg-mcp-server executable")
    arguments = parser.parse_args()

    asyncio.run(smoke_test_server(arguments.command))


if __name__ == "__main__":
    main()
