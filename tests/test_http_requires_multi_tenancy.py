"""Serving MCP over HTTP requires multi-tenancy, so no caller can act under a server-wide token."""

import os
from unittest.mock import patch

import pytest

from gg_mcp_server import run
from gg_mcp_server.server import build_http_app, build_server

# The configuration that used to fail open: an HTTP port and a server-side PAT, no multi-tenancy.
SHARED_IDENTITY_ENV = {
    "MCP_PORT": "8000",
    "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "server-wide-pat",
    "ENABLE_LOCAL_OAUTH": "false",
    "GITGUARDIAN_URL": "https://dashboard.gitguardian.com",
}


class TestHttpRequiresMultiTenancy:
    @pytest.mark.parametrize("multi_tenancy", [None, "false", ""], ids=["unset", "false", "empty"])
    def test_the_http_app_is_not_built_without_multi_tenancy(self, multi_tenancy):
        """
        GIVEN an HTTP deployment with a server-side PAT and multi-tenancy not enabled
        WHEN the production ASGI app is built
        THEN it refuses, naming MULTI_TENANCY_ENABLED
        """
        env = dict(SHARED_IDENTITY_ENV)
        if multi_tenancy is not None:
            env["MULTI_TENANCY_ENABLED"] = multi_tenancy
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(RuntimeError, match="MULTI_TENANCY_ENABLED=true"):
                build_http_app(build_server())

    def test_the_http_app_is_built_with_multi_tenancy(self):
        """
        GIVEN an HTTP deployment with MULTI_TENANCY_ENABLED=true
        WHEN the production ASGI app is built
        THEN it is built
        """
        with patch.dict(os.environ, {**SHARED_IDENTITY_ENV, "MULTI_TENANCY_ENABLED": "true"}, clear=True):
            assert build_http_app(build_server()) is not None

    def test_the_local_http_runner_refuses_before_starting(self):
        """
        GIVEN MCP_PORT set and multi-tenancy not enabled
        WHEN the server is started over HTTP with uvicorn
        THEN it refuses before building the server or binding the port
        """
        with patch.dict(os.environ, SHARED_IDENTITY_ENV, clear=True):
            with patch("uvicorn.run") as uvicorn_run, patch.object(run, "get_server") as get_server:
                with pytest.raises(RuntimeError, match="MULTI_TENANCY_ENABLED=true"):
                    run.run_mcp_server()

        uvicorn_run.assert_not_called()
        get_server.assert_not_called()
