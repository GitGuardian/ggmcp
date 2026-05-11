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


class Settings(BaseSettings):
    """Environment-backed configuration for gg-mcp."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
    )

    # --- GitGuardian core ---
    gitguardian_url: str = "https://dashboard.gitguardian.com"
    gitguardian_personal_access_token: str | None = None

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

    # --- System ---
    xdg_config_home: str | None = None

    # Note: Sentry config lives in :class:`SentrySettings` (instantiated lazily
    # inside ``init_sentry``) so a malformed ``SENTRY_*`` value cannot poison
    # unrelated code paths that build the main ``Settings``.

    # --- Derived helpers ---
    @property
    def is_oauth_enabled(self) -> bool:
        """OAuth is enabled by default; only an explicit non-"true" value disables it."""
        if self.enable_local_oauth is None:
            return True
        return self.enable_local_oauth.lower() == "true"

    @property
    def is_multi_tenant(self) -> bool:
        return self.multi_tenancy_enabled.lower() == "true"

    @property
    def use_dashboard_authenticated_page(self) -> bool:
        return self.gitguardian_use_dashboard_authenticated_page.lower() in ("true", "1", "yes")

    @property
    def scopes_str(self) -> str | None:
        """GITGUARDIAN_SCOPES with GITGUARDIAN_REQUESTED_SCOPES fallback."""
        return self.gitguardian_scopes or self.gitguardian_requested_scopes


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
