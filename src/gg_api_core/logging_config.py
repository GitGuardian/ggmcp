from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

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
_DEMOTED_LOGGERS = ("httpx", "httpcore", "mcp.server.lowlevel.server")


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


def configure_logging(*, log_level: str = "INFO", log_format: str | None = None, service: str = "ggmcp") -> None:
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
