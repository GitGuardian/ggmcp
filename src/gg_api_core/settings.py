"""Centralised settings for gg-mcp servers.

All environment-variable access goes through :class:`Settings`. Use
:func:`get_settings` rather than reading ``os.environ`` directly.

Precedence (highest first):
    1. Real environment variables (exported, inline, container env)
    2. Field defaults declared below

``get_settings()`` returns a fresh ``Settings`` instance on every call so
test fixtures using ``patch.dict(os.environ, ...)`` or
``monkeypatch.setenv`` continue to work without cache invalidation.
"""

import warnings
from enum import Enum
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

TRUTHY_ENV_VALUES = frozenset(
    {
        "true",
        "1",
        "yes",
    }
)


def string_env_to_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.lower() in TRUTHY_ENV_VALUES


class AuthMode(str, Enum):
    """Declared authentication mode for the MCP server.

    The mode is the single source of truth for transport and tenancy:

    - HTTP modes (``oauth-proxy``, ``header``) are multi-tenant by definition:
      the credential arrives per request, so a process-level fallback token
      would silently collapse every tenant onto one identity.
    - stdio modes (``env-pat``, ``local-oauth``) are single-tenant: a single
      process-level credential serves the whole server lifetime.

    ``MULTI_TENANCY_ENABLED`` is no longer an input; tenancy is a consequence
    of the mode (see :attr:`Settings.is_multi_tenant`).
    """

    OAUTH_PROXY = "oauth-proxy"
    HEADER = "header"
    ENV_PAT = "env-pat"
    LOCAL_OAUTH = "local-oauth"

    @property
    def is_multi_tenant(self) -> bool:
        """Whether this mode serves multiple identities per process."""
        return self in (AuthMode.OAUTH_PROXY, AuthMode.HEADER)

    @property
    def transport(self) -> str:
        """Transport implied by this mode: ``http`` or ``stdio``."""
        return "http" if self.is_multi_tenant else "stdio"


def _parse_auth_mode(value: str) -> AuthMode:
    """Parse a raw ``MCP_AUTH_MODE`` value into an :class:`AuthMode`.

    Accepts the canonical hyphenated spellings and their underscore variants
    (``oauth_proxy`` → ``oauth-proxy``), case-insensitively.
    """
    normalized = value.strip().lower().replace("_", "-")
    try:
        return AuthMode(normalized)
    except ValueError:
        valid = ", ".join(mode.value for mode in AuthMode)
        raise ValueError(f"Invalid MCP_AUTH_MODE={value!r}. Expected one of: {valid}") from None


def _warn_deprecated(old: str, new: str) -> None:
    """Emit a one-shot deprecation warning for a legacy selector var."""
    warnings.warn(
        f"{old} is deprecated; set {new} instead.",
        DeprecationWarning,
        stacklevel=3,
    )


class Settings(BaseSettings):
    """Environment-backed configuration for gg-mcp."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
    )

    # --- GitGuardian core ---
    gitguardian_url: str = "https://dashboard.gitguardian.com"
    gitguardian_api_url: str | None = None
    gitguardian_personal_access_token: str | None = None

    on_prem: str | None = Field(default=None, alias="IS_ON_PREM")

    # GITGUARDIAN_REQUESTED_SCOPES is the legacy name kept for backward compat.
    gitguardian_scopes: str | None = None
    gitguardian_requested_scopes: str | None = None

    gitguardian_login_path: str = "auth/login"
    gitguardian_token_name: str = "MCP Token"
    gitguardian_token_lifetime: str = "30"
    gitguardian_client_id: str = "ggshield_oauth"
    gitguardian_use_dashboard_authenticated_page: str = ""

    # --- MCP transport ---
    # Kept as str|None so callers can distinguish "unset" (stdio mode) from "set".
    mcp_port: str | None = None
    mcp_host: str = "127.0.0.1"
    # Declared authentication mode (oauth-proxy | header | env-pat | local-oauth).
    # When unset, the mode is inferred from the legacy selectors below for one
    # release cycle (see :attr:`auth_mode`).
    mcp_auth_mode: str | None = None
    multi_tenancy_enabled: str = ""
    # None ⇒ unset (default: True). Empty/anything-but-"true" ⇒ False.
    enable_local_oauth: str | None = None

    # --- OAuth proxy ---
    mcp_oauth_proxy_enabled: str | None = None
    mcp_base_url: str = "http://localhost:8000"
    mcp_oauth_token_name: str = "MCP server token (OAuth Proxy)"
    # Explicit 90 mirrors the server-side policy for DCR-issued tokens
    # (oauth2_access_token_max_lifetime: default and cap, per SI-3329). The local
    # flow's 30-day gitguardian_token_lifetime default must not leak into the
    # proxy — DCR tokens have a server backstop, local ones don't.
    mcp_oauth_token_lifetime: str = "90"

    # --- System ---
    xdg_config_home: str | None = None
    log_level: str = "INFO"
    # "json" or "console"; unset ⇒ auto (console on a TTY, else json)
    log_format: Literal["json", "console"] | None = None

    # --- Derived helpers ---
    @property
    def is_oauth_enabled(self) -> bool:
        """OAuth is enabled by default; only an explicit non-"true" value disables it."""
        if self.enable_local_oauth is None:
            return True
        return string_env_to_bool(self.enable_local_oauth)

    @property
    def is_on_prem(self) -> bool | None:
        """Explicit self-hosted/SaaS declaration, or None when IS_ON_PREM is unset."""
        if self.on_prem is None:
            return None
        return string_env_to_bool(self.on_prem)

    @property
    def is_multi_tenant(self) -> bool:
        """Whether the server serves multiple identities per process.

        Derived from the resolved :attr:`auth_mode` rather than declared
        separately: HTTP modes are multi-tenant, stdio modes are single-tenant.
        """
        return self.auth_mode.is_multi_tenant

    @property
    def auth_mode(self) -> AuthMode:
        """Resolve the effective authentication mode.

        ``MCP_AUTH_MODE`` wins when set. Otherwise the mode is inferred from
        the legacy selectors (``MCP_OAUTH_PROXY_ENABLED``, ``ENABLE_LOCAL_OAUTH``,
        ``GITGUARDIAN_PERSONAL_ACCESS_TOKEN``) with a deprecation warning, so
        existing deployments keep working for one release cycle.

        The inference also removes the old ladder surprise: a PAT alone now
        selects ``env-pat`` without requiring ``ENABLE_LOCAL_OAUTH=false``.
        """
        if self.mcp_auth_mode:
            return _parse_auth_mode(self.mcp_auth_mode)
        return self._infer_auth_mode_from_legacy()

    def _infer_auth_mode_from_legacy(self) -> AuthMode:
        """Map the legacy selector vars onto an :class:`AuthMode`."""
        if self.is_oauth_proxy_enabled:
            _warn_deprecated("MCP_OAUTH_PROXY_ENABLED", "MCP_AUTH_MODE=oauth-proxy")
            return AuthMode.OAUTH_PROXY

        if self.enable_local_oauth is not None and not string_env_to_bool(self.enable_local_oauth):
            # ENABLE_LOCAL_OAUTH explicitly false: PAT → env-pat, else header.
            _warn_deprecated("ENABLE_LOCAL_OAUTH", "MCP_AUTH_MODE")
            if self.gitguardian_personal_access_token:
                return AuthMode.ENV_PAT
            return AuthMode.HEADER

        if self.enable_local_oauth is not None:
            _warn_deprecated("ENABLE_LOCAL_OAUTH", "MCP_AUTH_MODE")

        # Default: a PAT selects env-pat, otherwise local-oauth. This removes
        # the ladder surprise where a PAT alone did not select PAT mode.
        if self.gitguardian_personal_access_token:
            return AuthMode.ENV_PAT
        return AuthMode.LOCAL_OAUTH

    def validate_auth_mode(self) -> None:
        """Refuse to boot on a mode/var combination that cannot be safe.

        Enforces each mode's required and forbidden variables and rejects a
        ``MULTI_TENANCY_ENABLED`` value that contradicts the derived tenancy.
        Called from :func:`gg_api_core.mcp_server.get_mcp_server` at startup.

        Raises:
            ValueError: if the resolved mode's configuration is invalid.
        """
        # HTTP transport (MCP_PORT set) without a declared mode is ambiguous:
        # the legacy HTTP selectors still map onto HTTP modes, but a bare
        # MCP_PORT with no mode and no legacy selector must be refused
        # explicitly rather than silently inferring a stdio mode.
        if (
            not self.mcp_auth_mode
            and self.mcp_port
            and not self.is_oauth_proxy_enabled
            and not (self.enable_local_oauth is not None and not string_env_to_bool(self.enable_local_oauth))
        ):
            raise ValueError(
                "MCP_PORT is set but MCP_AUTH_MODE is not declared. "
                "Declare MCP_AUTH_MODE=oauth-proxy or MCP_AUTH_MODE=header for HTTP transport."
            )

        mode = self.auth_mode

        # MULTI_TENANCY_ENABLED (deprecated) must agree with the derived tenancy.
        if self.multi_tenancy_enabled:
            _warn_deprecated("MULTI_TENANCY_ENABLED", "MCP_AUTH_MODE")
            declared = string_env_to_bool(self.multi_tenancy_enabled)
            if declared != mode.is_multi_tenant:
                raise ValueError(
                    f"MULTI_TENANCY_ENABLED={self.multi_tenancy_enabled!r} contradicts "
                    f"MCP_AUTH_MODE={mode.value} (tenancy is "
                    f"{'multi' if mode.is_multi_tenant else 'single'}-tenant). "
                    "Unset MULTI_TENANCY_ENABLED; tenancy is derived from the mode."
                )

        # Required variables.
        if mode in (AuthMode.OAUTH_PROXY, AuthMode.HEADER):
            if not self.mcp_port:
                raise ValueError(f"MCP_AUTH_MODE={mode.value} requires MCP_PORT to be set (HTTP transport).")
        elif mode is AuthMode.ENV_PAT:
            if not self.gitguardian_personal_access_token:
                raise ValueError("MCP_AUTH_MODE=env-pat requires GITGUARDIAN_PERSONAL_ACCESS_TOKEN to be set.")

        # Forbidden variables: a server-side PAT in an HTTP mode would collapse
        # every tenant onto one identity; MCP_PORT in a stdio mode is a stray
        # credential waiting for a flag to drop.
        if mode in (AuthMode.OAUTH_PROXY, AuthMode.HEADER):
            if self.gitguardian_personal_access_token:
                raise ValueError(
                    f"MCP_AUTH_MODE={mode.value} is multi-tenant; a server-side "
                    "GITGUARDIAN_PERSONAL_ACCESS_TOKEN would collapse every tenant onto "
                    "one identity. Unset it or use a single-tenant mode (env-pat / local-oauth)."
                )
        elif mode in (AuthMode.ENV_PAT, AuthMode.LOCAL_OAUTH):
            if self.mcp_port:
                raise ValueError(
                    f"MCP_AUTH_MODE={mode.value} is single-tenant (stdio); MCP_PORT must not be set. "
                    "Use an HTTP mode (oauth-proxy / header) for HTTP transport."
                )

    @property
    def use_dashboard_authenticated_page(self) -> bool:
        return string_env_to_bool(self.gitguardian_use_dashboard_authenticated_page)

    @property
    def is_oauth_proxy_enabled(self) -> bool:
        return string_env_to_bool(self.mcp_oauth_proxy_enabled)

    @property
    def requested_scopes(self) -> list[str]:
        """Scopes the user asked for via env, parsed and validated.

        Reads ``GITGUARDIAN_SCOPES`` (with ``GITGUARDIAN_REQUESTED_SCOPES``
        as a legacy fallback), splits on commas, and validates each entry
        against :data:`gg_api_core.scopes.ALL_SCOPES`. Returns an empty
        list when neither env var is set.

        Raises:
            ValueError: if any requested scope is not a known scope.
        """
        from .scopes import validate_scopes

        raw = self.gitguardian_scopes or self.gitguardian_requested_scopes
        if not raw:
            return []
        return validate_scopes(raw)

    @property
    def effective_scopes(self) -> list[str]:
        """Final scope set the OAuth flow should request.

        - If the user explicitly set ``GITGUARDIAN_SCOPES``, that list is used as-is.
        - Otherwise the full :data:`ALL_SCOPES` set is requested.
        - Non-local self-hosted instances are capped to
          :data:`SCOPES_SUPPORTED_IN_SELF_HOSTED` (self-hosted releases lag
          behind SaaS, so a scope available in SaaS may not yet be available
          in self-hosted; we intersect to avoid requesting unknown scopes).

        The dashboard's OAuth consent UI ultimately decides which scopes the
        access token receives; runtime tool visibility is then driven by the
        token's actual scopes via the scope-filtering middleware.
        """
        # Lazy import: ``host`` and ``scopes`` could otherwise cycle through
        # this module via their own imports.
        from .host import is_local_instance, is_self_hosted_instance
        from .scopes import ALL_SCOPES, SCOPES_SUPPORTED_IN_SELF_HOSTED

        requested = self.requested_scopes

        if is_self_hosted_instance(self.gitguardian_url) and not is_local_instance(self.gitguardian_url):
            if not requested:
                return list(SCOPES_SUPPORTED_IN_SELF_HOSTED)
            return sorted(set(SCOPES_SUPPORTED_IN_SELF_HOSTED) & set(requested))

        return requested if requested else list(ALL_SCOPES)


class SentrySettings(BaseSettings):
    """Sentry-specific settings, instantiated lazily by ``init_sentry``.

    Kept separate from :class:`Settings` so that malformed numeric values
    (e.g. ``SENTRY_TRACES_SAMPLE_RATE=abc``) only break the Sentry code
    path, not every caller that needs an unrelated setting.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTRY_",
        case_sensitive=False,
        extra="ignore",
    )

    dsn: str | None = None
    environment: str = "production"
    release: str | None = None
    traces_sample_rate: float = 0.1
    profiles_sample_rate: float = 0.1


def get_settings() -> Settings:
    """Build a fresh :class:`Settings` from the current environment.

    Not cached: tests routinely mutate ``os.environ`` and expect each call
    to observe the latest values.
    """
    return Settings()
