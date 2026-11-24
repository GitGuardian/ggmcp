from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import anyio
import structlog
from starlette.requests import ClientDisconnect
from structlog.types import EventDict, Processor, WrappedLogger

from gg_api_core.client import DownstreamUnauthorizedError, caused_by_downstream_401
from gg_api_core.sanitization import scrub_by_name, scrub_by_value
from gg_api_core.version import APP_VERSION

if TYPE_CHECKING:
    from gg_api_core.settings import Settings

_RESERVED_KEYS = frozenset(
    {
        "event",
        "level",
        "logger",
        "logger_name",
        "timestamp",
        "exc_info",
        "exception",
        "exception_cls",
        "stack",
        "stack_info",
        "_record",
        "_from_structlog",
    }
)


# Their per-request INFO lines are replaced by structured events.
_DEMOTED_LOGGERS = ("httpx", "httpcore", "mcp.server.lowlevel.server", "mcp.server.streamable_http")

# A client that hangs up mid-request makes the MCP SDK log an ERROR with a traceback:
# ClientDisconnect while the request body is read ("Error handling POST request"), or
# ClosedResourceError once the answer can no longer be sent ("Stateless session crashed").
# Nobody is left to answer and nothing failed on our side, so those records go out as
# WARNING. Any other error from these loggers keeps its level.
_CLIENT_DISCONNECT_LOGGERS = frozenset({"mcp.server.streamable_http", "mcp.server.streamable_http_manager"})
_CLIENT_DISCONNECT_ERRORS = (ClientDisconnect, anyio.ClosedResourceError, anyio.BrokenResourceError)


def _is_client_disconnect(exception: BaseException | None) -> bool:
    """Whether the exception, every exception of a group included, means the client went away."""
    if isinstance(exception, BaseExceptionGroup):
        return all(_is_client_disconnect(nested) for nested in exception.exceptions)
    return isinstance(exception, _CLIENT_DISCONNECT_ERRORS)


def _demote_client_disconnects(record: logging.LogRecord) -> bool:
    """Log a client disconnect reported by the MCP SDK as WARNING instead of ERROR."""
    if (
        record.levelno >= logging.ERROR
        and record.name in _CLIENT_DISCONNECT_LOGGERS
        and record.exc_info
        and _is_client_disconnect(record.exc_info[1])
    ):
        record.levelno = logging.WARNING
        record.levelname = "WARNING"
    return True


# The MCP SDK logs an ERROR with a traceback each time a client sends an expired or
# revoked token. That is not a server error, and mcp_request_failed already logs it,
# so this filter drops the SDK's record (LOG_LEVEL=DEBUG keeps it, as a WARNING).
# A different exception raised while handling such a token is still logged, as a WARNING.
_REJECTED_TOKEN_LOGGERS = frozenset({"mcp.server.runner", "mcp.shared.jsonrpc_dispatcher"})


def _drop_rejected_tokens(record: logging.LogRecord) -> bool:
    """Drop the MCP SDK's error record for a rejected token."""
    if (
        record.levelno >= logging.ERROR
        and record.name in _REJECTED_TOKEN_LOGGERS
        and record.exc_info
        and caused_by_downstream_401(record.exc_info[1])
    ):
        rejected_token_itself = isinstance(record.exc_info[1], DownstreamUnauthorizedError)
        if rejected_token_itself and not logging.getLogger().isEnabledFor(logging.DEBUG):
            return False
        record.levelno = logging.WARNING
        record.levelname = "WARNING"
    return True


def _scrub_event(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Scrub every field: reserved keys by value, app keys by name and value.

    Reserved keys carry structlog plumbing and free-text such as the log
    message and rendered tracebacks, where a name match would be meaningless;
    they only get value scrubbing. App-provided keys are redacted when their
    name is sensitive, and surviving string values are value-scrubbed too.
    """
    for key, value in event_dict.items():
        if key in _RESERVED_KEYS:
            event_dict[key] = scrub_by_value(value)
        else:
            event_dict[key] = scrub_by_name(str(key), value)
    return event_dict


def _add_exception_cls(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    exc_info = event_dict.get("exc_info")
    if not exc_info or "exception_cls" in event_dict:
        return event_dict
    exc = sys.exc_info() if exc_info is True else exc_info
    exc_type = exc[0] if isinstance(exc, tuple) else type(exc)
    if exc_type is not None:
        module = getattr(exc_type, "__module__", "")
        name = getattr(exc_type, "__name__", str(exc_type))
        event_dict["exception_cls"] = name if module in ("builtins", "") else f"{module}.{name}"
    return event_dict


def configure_logging(
    *, log_level: str = "INFO", log_format: str | None = None, service: str = "gg-mcp-server"
) -> None:
    def _add_gg_fields(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
        event_dict["gg_service"] = service
        event_dict["gg_version"] = APP_VERSION or "unknown"
        return event_dict

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso"),
        _add_gg_fields,
        structlog.processors.StackInfoRenderer(),
        _add_exception_cls,
        structlog.processors.format_exc_info,
        _scrub_event,
    ]

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    console = log_format == "console" or (log_format is None and sys.stderr.isatty())
    renderer = structlog.dev.ConsoleRenderer() if console else structlog.processors.JSONRenderer()
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.name = "ggmcp-log"
    handler.setFormatter(formatter)
    handler.addFilter(_demote_client_disconnects)
    handler.addFilter(_drop_rejected_tokens)

    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if h.name != "ggmcp-log"]
    root.addHandler(handler)
    root_level = logging.getLevelNamesMapping().get(log_level.upper(), logging.INFO)
    root.setLevel(root_level)

    # Preserve raw third-party request logs only when DEBUG is requested.
    demoted_level = logging.NOTSET if root_level <= logging.DEBUG else logging.WARNING
    for name in _DEMOTED_LOGGERS:
        logging.getLogger(name).setLevel(demoted_level)


def configure_logging_from_settings(settings: Settings) -> None:
    configure_logging(log_level=settings.log_level, log_format=settings.log_format)
