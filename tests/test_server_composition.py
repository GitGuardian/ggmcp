"""Regression tests for the production server composition entry point."""

from typing import Any

from gg_mcp_server import server


def test_get_server_initializes_observability_before_building_and_caches(monkeypatch):
    """
    GIVEN the production server entry point
    WHEN get_server is called more than once
    THEN observability is initialized before composition and the result is cached
    """
    events: list[str] = []
    expected_settings = object()
    expected_server = object()

    def configure_logging(settings: Any) -> None:
        assert settings is expected_settings
        events.append("logging")

    def build_server() -> object:
        events.append("build")
        return expected_server

    monkeypatch.setattr(server, "init_sentry", lambda: events.append("sentry"))
    monkeypatch.setattr(server, "get_settings", lambda: expected_settings)
    monkeypatch.setattr(server, "configure_logging_from_settings", configure_logging)
    monkeypatch.setattr(server, "build_server", build_server)
    server.get_server.cache_clear()

    try:
        first_result = server.get_server()
        second_result = server.get_server()
    finally:
        server.get_server.cache_clear()

    assert first_result is expected_server
    assert second_result is expected_server
    assert events == ["sentry", "logging", "build"]
