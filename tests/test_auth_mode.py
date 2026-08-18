"""Tests for the MCP_AUTH_MODE resolution and boot-time validation.

The auth mode is the single source of truth for transport and tenancy. These
tests pin the explicit-mode parsing, the legacy back-compat inference (with
deprecation warnings), and the boot asserts that refuse unsafe combinations.
"""

import os
from unittest.mock import patch

import pytest

from gg_api_core.settings import AuthMode, get_settings


def _settings(env: dict[str, str]) -> object:
    with patch.dict(os.environ, env, clear=True):
        return get_settings()


class TestAuthModeEnum:
    """The enum's derived tenancy and transport."""

    @pytest.mark.parametrize(
        ("mode", "multi_tenant", "transport"),
        [
            (AuthMode.OAUTH_PROXY, True, "http"),
            (AuthMode.HEADER, True, "http"),
            (AuthMode.ENV_PAT, False, "stdio"),
            (AuthMode.LOCAL_OAUTH, False, "stdio"),
        ],
    )
    def test_derived_tenancy_and_transport(self, mode, multi_tenant, transport):
        """
        GIVEN an AuthMode
        WHEN its is_multi_tenant and transport are read
        THEN HTTP modes are multi-tenant, stdio modes are single-tenant
        """
        assert mode.is_multi_tenant is multi_tenant
        assert mode.transport == transport


class TestExplicitModeResolution:
    """MCP_AUTH_MODE wins and is parsed leniently."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("oauth-proxy", AuthMode.OAUTH_PROXY),
            ("header", AuthMode.HEADER),
            ("env-pat", AuthMode.ENV_PAT),
            ("local-oauth", AuthMode.LOCAL_OAUTH),
            # underscore and case variants are accepted
            ("oauth_proxy", AuthMode.OAUTH_PROXY),
            ("ENV_PAT", AuthMode.ENV_PAT),
            ("Local-OAuth", AuthMode.LOCAL_OAUTH),
        ],
    )
    def test_explicit_mode_parses(self, raw, expected):
        """
        GIVEN MCP_AUTH_MODE set to a valid (possibly variant) spelling
        WHEN auth_mode is read
        THEN it resolves to the matching AuthMode
        """
        assert _settings({"MCP_AUTH_MODE": raw}).auth_mode is expected

    def test_invalid_mode_raises(self):
        """
        GIVEN MCP_AUTH_MODE set to an unknown value
        WHEN auth_mode is read
        THEN it raises ValueError listing the valid modes
        """
        with pytest.raises(ValueError, match="Invalid MCP_AUTH_MODE"):
            _settings({"MCP_AUTH_MODE": "bogus"}).auth_mode


class TestLegacyInference:
    """Back-compat mapping of the deprecated selector vars."""

    def test_oauth_proxy_enabled_maps_to_oauth_proxy(self):
        """
        GIVEN MCP_OAUTH_PROXY_ENABLED=true and no MCP_AUTH_MODE
        WHEN auth_mode is read
        THEN it resolves to oauth-proxy with a deprecation warning
        """
        with pytest.warns(DeprecationWarning, match="MCP_OAUTH_PROXY_ENABLED"):
            assert _settings({"MCP_OAUTH_PROXY_ENABLED": "true"}).auth_mode is AuthMode.OAUTH_PROXY

    def test_enable_local_oauth_false_with_pat_maps_to_env_pat(self):
        """
        GIVEN ENABLE_LOCAL_OAUTH=false and a PAT, no MCP_AUTH_MODE
        WHEN auth_mode is read
        THEN it resolves to env-pat
        """
        with pytest.warns(DeprecationWarning, match="ENABLE_LOCAL_OAUTH"):
            assert (
                _settings({"ENABLE_LOCAL_OAUTH": "false", "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x"}).auth_mode
                is AuthMode.ENV_PAT
            )

    def test_enable_local_oauth_false_without_pat_maps_to_header(self):
        """
        GIVEN ENABLE_LOCAL_OAUTH=false and no PAT, no MCP_AUTH_MODE
        WHEN auth_mode is read
        THEN it resolves to header (HTTP, multi-tenant)
        """
        with pytest.warns(DeprecationWarning, match="ENABLE_LOCAL_OAUTH"):
            assert _settings({"ENABLE_LOCAL_OAUTH": "false"}).auth_mode is AuthMode.HEADER

    def test_pat_alone_maps_to_env_pat(self):
        """
        GIVEN a PAT with no MCP_AUTH_MODE and no ENABLE_LOCAL_OAUTH
        WHEN auth_mode is read
        THEN it resolves to env-pat (the old ladder surprise is gone)
        """
        assert _settings({"GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x"}).auth_mode is AuthMode.ENV_PAT

    def test_nothing_set_maps_to_local_oauth(self):
        """
        GIVEN no auth-related env vars at all
        WHEN auth_mode is read
        THEN it resolves to local-oauth (single-tenant default)
        """
        assert _settings({}).auth_mode is AuthMode.LOCAL_OAUTH


class TestValidateAuthMode:
    """Boot asserts refuse unsafe mode/var combinations."""

    def test_header_requires_mcp_port(self):
        """
        GIVEN MCP_AUTH_MODE=header without MCP_PORT
        WHEN validate_auth_mode is called
        THEN it raises ValueError
        """
        with pytest.raises(ValueError, match="MCP_PORT"):
            _settings({"MCP_AUTH_MODE": "header"}).validate_auth_mode()

    def test_oauth_proxy_requires_mcp_port(self):
        """
        GIVEN MCP_AUTH_MODE=oauth-proxy without MCP_PORT
        WHEN validate_auth_mode is called
        THEN it raises ValueError
        """
        with pytest.raises(ValueError, match="MCP_PORT"):
            _settings({"MCP_AUTH_MODE": "oauth-proxy"}).validate_auth_mode()

    def test_env_pat_requires_pat(self):
        """
        GIVEN MCP_AUTH_MODE=env-pat without a PAT
        WHEN validate_auth_mode is called
        THEN it raises ValueError
        """
        with pytest.raises(ValueError, match="GITGUARDIAN_PERSONAL_ACCESS_TOKEN"):
            _settings({"MCP_AUTH_MODE": "env-pat"}).validate_auth_mode()

    def test_http_mode_forbids_server_side_pat(self):
        """
        GIVEN MCP_AUTH_MODE=header with a server-side PAT
        WHEN validate_auth_mode is called
        THEN it raises ValueError (the PAT would collapse every tenant)
        """
        with pytest.raises(ValueError, match="collapse every tenant"):
            _settings(
                {"MCP_AUTH_MODE": "header", "MCP_PORT": "8000", "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x"}
            ).validate_auth_mode()

    def test_stdio_mode_forbids_mcp_port(self):
        """
        GIVEN MCP_AUTH_MODE=env-pat with MCP_PORT set
        WHEN validate_auth_mode is called
        THEN it raises ValueError
        """
        with pytest.raises(ValueError, match="MCP_PORT"):
            _settings(
                {"MCP_AUTH_MODE": "env-pat", "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x", "MCP_PORT": "8000"}
            ).validate_auth_mode()

    def test_multi_tenancy_enabled_contradiction_raises(self):
        """
        GIVEN MCP_AUTH_MODE=env-pat but MULTI_TENANCY_ENABLED=true
        WHEN validate_auth_mode is called
        THEN it raises ValueError (tenancy is derived, not declared)
        """
        with pytest.raises(ValueError, match="contradicts"):
            _settings(
                {
                    "MCP_AUTH_MODE": "env-pat",
                    "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x",
                    "MULTI_TENANCY_ENABLED": "true",
                }
            ).validate_auth_mode()

    def test_http_transport_without_declared_mode_raises(self):
        """
        GIVEN MCP_PORT set but no MCP_AUTH_MODE and no legacy HTTP selector
        WHEN validate_auth_mode is called
        THEN it raises ValueError asking for a declared HTTP mode
        """
        with pytest.raises(ValueError, match="MCP_AUTH_MODE is not declared"):
            _settings({"MCP_PORT": "8000"}).validate_auth_mode()

    @pytest.mark.parametrize(
        "env",
        [
            {"MCP_AUTH_MODE": "oauth-proxy", "MCP_PORT": "8000"},
            {"MCP_AUTH_MODE": "header", "MCP_PORT": "8000"},
            {"MCP_AUTH_MODE": "env-pat", "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "x"},
            {"MCP_AUTH_MODE": "local-oauth"},
        ],
    )
    def test_valid_configurations_pass(self, env):
        """
        GIVEN a valid mode/var combination
        WHEN validate_auth_mode is called
        THEN it does not raise
        """
        _settings(env).validate_auth_mode()
