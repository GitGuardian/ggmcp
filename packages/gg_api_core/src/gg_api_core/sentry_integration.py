"""Optional Sentry integration for error tracking and monitoring.

This module provides optional Sentry instrumentation that can be enabled
via environment variables. It's designed to be non-invasive and vendor-neutral,
allowing users to opt-in to Sentry monitoring without forcing a dependency.

Environment Variables:
    SENTRY_DSN: Sentry Data Source Name (required to enable Sentry)
    SENTRY_ENVIRONMENT: Environment name (e.g., production, development)
    SENTRY_RELEASE: Release version or commit SHA
    SENTRY_TRACES_SAMPLE_RATE: Sampling rate for performance traces (0.0 to 1.0)
    SENTRY_PROFILES_SAMPLE_RATE: Sampling rate for profiling (0.0 to 1.0)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .sanitization import SENSITIVE_DATA_PLACEHOLDER, scrub_by_name, scrub_by_value
from .settings import SentrySettings

if TYPE_CHECKING:
    from sentry_sdk.types import Event, Hint

logger = logging.getLogger(__name__)


_MAX_SCRUB_DEPTH = 12


def _scrub_sentry_payload(value: Any, depth: int = 0) -> Any:
    """Value-scrub strings recursively at the Sentry SDK boundary."""
    if depth >= _MAX_SCRUB_DEPTH:
        return SENSITIVE_DATA_PLACEHOLDER
    if isinstance(value, str):
        return scrub_by_value(value)
    if isinstance(value, dict):
        return {key: _scrub_sentry_payload(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub_sentry_payload(item, depth + 1) for item in value)
    return value


def _scrub_breadcrumb(breadcrumb: dict[str, Any], hint: Hint) -> dict[str, Any]:
    """Scrub breadcrumb values and sensitive logging ``data`` fields."""
    data = breadcrumb.get("data")
    if isinstance(data, dict):
        breadcrumb["data"] = {str(key): scrub_by_name(str(key), value) for key, value in data.items()}
    return _scrub_sentry_payload(breadcrumb)


def _scrub_sentry_event(event: Event, hint: Hint) -> Event:
    """Scrub an event before sending it to Sentry."""
    return _scrub_sentry_payload(event)


def init_sentry() -> bool:
    """
    Initialize Sentry SDK if configured via environment variables.

    This function attempts to import and configure Sentry SDK only if
    SENTRY_DSN is provided. It gracefully handles missing sentry-sdk
    installation and logs appropriate messages.

    Returns:
        bool: True if Sentry was successfully initialized, False otherwise

    Example:
        >>> import os
        >>> os.environ["SENTRY_DSN"] = "https://..."
        >>> init_sentry()
        True
    """
    sentry_settings = SentrySettings()
    dsn = sentry_settings.dsn

    if not dsn:
        logger.debug("SENTRY_DSN not configured, skipping Sentry initialization")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError:
        logger.warning("Sentry SDK not installed")
        return False

    environment = sentry_settings.environment
    release = sentry_settings.release
    traces_sample_rate = sentry_settings.traces_sample_rate
    profiles_sample_rate = sentry_settings.profiles_sample_rate

    # Logs provide breadcrumbs only. MCPIntegration owns tool-failure events.
    logging_integration = LoggingIntegration(level=logging.INFO, event_level=None)

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            release=release,
            traces_sample_rate=traces_sample_rate,
            profiles_sample_rate=profiles_sample_rate,
            integrations=[logging_integration],
            include_local_variables=False,
            before_send=_scrub_sentry_event,
            before_breadcrumb=_scrub_breadcrumb,
            # Automatically capture unhandled exceptions
            send_default_pii=False,  # Don't send personally identifiable information by default
        )

        logger.info(
            f"Sentry initialized successfully for environment: {environment}"
            + (f", release: {release}" if release else "")
        )
        return True

    except Exception as e:
        logger.exception(f"Failed to initialize Sentry: {str(e)}")
        return False


def set_sentry_context(key: str, value: Any) -> None:
    """
    Set additional context for Sentry error reporting.

    This is a convenience wrapper that safely sets context even if
    Sentry is not initialized.

    Args:
        key: Context key (e.g., "user", "workspace", "api_token")
        value: Context value (can be dict, string, etc.)

    Example:
        >>> set_sentry_context("workspace", {"id": "123", "name": "acme"})
    """
    try:
        import sentry_sdk

        sentry_sdk.set_context(key, value)
    except ImportError:
        # Sentry not installed, silently skip
        pass
    except Exception as e:
        logger.debug(f"Failed to set Sentry context: {str(e)}")


def set_sentry_user(user_info: dict[str, Any]) -> None:
    """
    Set user information for Sentry error reporting.

    This is a convenience wrapper that safely sets user info even if
    Sentry is not initialized.

    Args:
        user_info: Dictionary with user information (id, email, username, etc.)

    Example:
        >>> set_sentry_user({"id": "123", "email": "user@example.com"})
    """
    try:
        import sentry_sdk

        sentry_sdk.set_user(user_info)
    except ImportError:
        # Sentry not installed, silently skip
        pass
    except Exception as e:
        logger.debug(f"Failed to set Sentry user: {str(e)}")


def capture_exception(exception: Exception, **kwargs: Any) -> None:
    """
    Manually capture an exception to Sentry.

    This is useful for handled exceptions that you still want to track.

    Args:
        exception: The exception to capture
        **kwargs: Additional context to attach to the event

    Example:
        >>> try:
        ...     risky_operation()
        ... except ValueError as e:
        ...     capture_exception(e, extra={"operation": "risky_operation"})
        ...     handle_error(e)
    """
    try:
        import sentry_sdk

        sentry_sdk.capture_exception(exception, **kwargs)
    except ImportError:
        # Sentry not installed, silently skip
        pass
    except Exception as e:
        logger.debug(f"Failed to capture exception in Sentry: {str(e)}")
