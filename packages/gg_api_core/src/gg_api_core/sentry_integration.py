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

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


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
    dsn = os.environ.get("SENTRY_DSN")

    if not dsn:
        logger.debug("SENTRY_DSN not configured, skipping Sentry initialization")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError:
        logger.warning("Sentry SDK not installed")
        return False

    # Get optional configuration from environment
    environment = os.environ.get("SENTRY_ENVIRONMENT", "production")
    release = os.environ.get("SENTRY_RELEASE")
    traces_sample_rate = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1"))
    profiles_sample_rate = float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "0.1"))

    # Configure logging integration
    logging_integration = LoggingIntegration(
        level=logging.INFO,  # Capture info and above as breadcrumbs
        event_level=logging.ERROR,  # Send errors as events
    )

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            release=release,
            traces_sample_rate=traces_sample_rate,
            profiles_sample_rate=profiles_sample_rate,
            integrations=[logging_integration],
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


def capture_exception(exception: Exception, **kwargs) -> None:
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
