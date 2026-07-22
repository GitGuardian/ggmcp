from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from gg_api_core.sanitization import scrub_by_name

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


def _sanitize_event_dict(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    for key in list(event_dict.keys()):
        if key not in _RESERVED_KEYS:
            event_dict[key] = scrub_by_name(str(key), event_dict[key])
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
    def _add_service(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
        event_dict["gg_service"] = service
        return event_dict

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso"),
        _add_service,
        structlog.processors.StackInfoRenderer(),
        _add_exception_cls,
        structlog.processors.format_exc_info,
        _sanitize_event_dict,
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
    root.setLevel(logging.getLevelNamesMapping().get(log_level.upper(), logging.INFO))


def configure_logging_from_settings(settings: Settings) -> None:
    configure_logging(log_level=settings.log_level, log_format=settings.log_format)
