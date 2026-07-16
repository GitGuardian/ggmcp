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

    on_prem: str | None = None

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
    multi_tenancy_enabled: str = ""
    # None ⇒ unset (default: True). Empty/anything-but-"true" ⇒ False.
    enable_local_oauth: str | None = None

    # --- OAuth proxy ---
    mcp_oauth_proxy_enabled: str | None = None
    mcp_base_url: str = "http://localhost:8000"

    # --- System ---
    xdg_config_home: str | None = None

    # --- Derived helpers ---
    @property
    def is_oauth_enabled(self) -> bool:
        """OAuth is enabled by default; only an explicit non-"true" value disables it."""
        if self.enable_local_oauth is None:
            return True
        return string_env_to_bool(self.enable_local_oauth)

    @property
    def is_on_prem(self) -> bool | None:
        """Explicit self-hosted/SaaS declaration, or None when ON_PREM is unset."""
        if self.on_prem is None:
            return None
        return string_env_to_bool(self.on_prem)

    @property
    def is_multi_tenant(self) -> bool:
        return string_env_to_bool(self.multi_tenancy_enabled)

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
