"""Gunicorn configuration and custom logger for MCP server.

This module provides a custom logger class for gunicorn that integrates
with Python's logging system for consistent log formatting.
"""

import logging


class GunicornLogger:
    """Custom logger class for gunicorn.

    This logger integrates gunicorn's logging with Python's standard logging
    to ensure consistent log formatting across the application.
    """

    def __init__(self, cfg):
        """Initialize the GunicornLogger.

        Args:
            cfg: Gunicorn configuration object
        """
        self.cfg = cfg
        self._error_log = None
        self._access_log = None

    @property
    def error_log(self):
        """Get the error logger."""
        if not self._error_log:
            self._error_log = logging.getLogger("gunicorn.error")
        return self._error_log

    @property
    def access_log(self):
        """Get the access logger."""
        if not self._access_log:
            self._access_log = logging.getLogger("gunicorn.access")
        return self._access_log

    def critical(self, msg, *args, **kwargs):
        """Log critical message."""
        self.error_log.critical(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """Log error message."""
        self.error_log.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """Log warning message."""
        self.error_log.warning(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """Log info message."""
        self.error_log.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        """Log debug message."""
        self.error_log.debug(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        """Log exception message."""
        self.error_log.exception(msg, *args, **kwargs)

    def log(self, lvl, msg, *args, **kwargs):
        """Log message at specific level."""
        self.error_log.log(lvl, msg, *args, **kwargs)

    def access(self, resp, req, environ, request_time):
        """Log access information."""
        self.access_log.info(
            '%s - "%s %s %s" %d',
            environ.get("REMOTE_ADDR", "-"),
            environ.get("REQUEST_METHOD", "-"),
            environ.get("PATH_INFO", "-"),
            environ.get("SERVER_PROTOCOL", "-"),
            resp.status_code,
        )

    def reopen_files(self):
        """Reopen log files (for log rotation)."""
        pass

    def close_on_exec(self):
        """Close log files on exec."""
        pass
