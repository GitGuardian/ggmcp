"""Gunicorn configuration and custom logger for MCP server.

This module provides a custom logger class for gunicorn that integrates
with Python's logging system for consistent log formatting.
"""

import logging
from typing import Any


class GunicornLogger:
    """Custom logger class for gunicorn.

    This logger integrates gunicorn's logging with Python's standard logging
    to ensure consistent log formatting across the application.
    """

    def __init__(self, cfg: Any) -> None:
        """Initialize the GunicornLogger.

        Args:
            cfg: Gunicorn configuration object
        """
        self.cfg = cfg
        self._error_log: logging.Logger | None = None
        self._access_log: logging.Logger | None = None

    @property
    def error_log(self) -> logging.Logger:
        """Get the error logger."""
        if not self._error_log:
            self._error_log = logging.getLogger("gunicorn.error")
        return self._error_log

    @property
    def access_log(self) -> logging.Logger:
        """Get the access logger."""
        if not self._access_log:
            self._access_log = logging.getLogger("gunicorn.access")
        return self._access_log

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        self.error_log.critical(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        self.error_log.error(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        self.error_log.warning(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        self.error_log.info(msg, *args, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        self.error_log.debug(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log exception message."""
        self.error_log.exception(msg, *args, **kwargs)

    def log(self, lvl: int, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log message at specific level."""
        self.error_log.log(lvl, msg, *args, **kwargs)

    def access(self, resp: Any, req: Any, environ: dict[str, Any], request_time: Any) -> None:
        """Log access information."""
        self.access_log.info(
            '%s - "%s %s %s" %d',
            environ.get("REMOTE_ADDR", "-"),
            environ.get("REQUEST_METHOD", "-"),
            environ.get("PATH_INFO", "-"),
            environ.get("SERVER_PROTOCOL", "-"),
            resp.status_code,
        )

    def reopen_files(self) -> None:
        """Reopen log files (for log rotation)."""
        pass

    def close_on_exec(self) -> None:
        """Close log files on exec."""
        pass
