"""Script to run the MCP server in HTTP mode. For PyCharm debugging for example"""
import os

# Set environment variables before importing
os.environ["GITGUARDIAN_URL"] = os.environ.get("GITGUARDIAN_URL", "http://127.0.0.1:3000")
os.environ["ENABLE_LOCAL_OAUTH"] = os.environ.get("ENABLE_LOCAL_OAUTH", "false")
os.environ["MCP_PORT"] = os.environ.get("MCP_PORT", "8088")
os.environ["MCP_HOST"] = os.environ.get("MCP_HOST", "127.0.0.1")

if __name__ == "__main__":
    # For SecOps server:
    from secops_mcp_server.server import run_mcp_server

    # Or for Developer server:
    # from developer_mcp_server.server import run_mcp_server

    # Run the server
    run_mcp_server()