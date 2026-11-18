"""Grading of tool failures into queryable fields."""

import httpx
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError

from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.log_context import classify_failure
from gg_api_core.model_arguments import ToolBodyError
from gg_api_core.redirects import CrossOriginRedirectError
from gg_api_core.scopes import MissingScopesError


def _caused_by(outer: BaseException, cause: BaseException) -> BaseException:
    outer.__cause__ = cause
    return outer


def _status_error(status: int, body: dict | str | None = None) -> httpx.HTTPStatusError:
    """An HTTPStatusError shaped like one httpx raises from raise_for_status."""
    request = httpx.Request("GET", "https://api.gitguardian.com/v1/incidents/secrets")
    if isinstance(body, dict):
        response = httpx.Response(status, json=body, request=request)
    else:
        response = httpx.Response(status, text=body or "", request=request)
    return httpx.HTTPStatusError("error", request=request, response=response)


class TestClassifyFailure:
    def test_reports_the_exception_class(self):
        """
        GIVEN a plain exception
        WHEN it is classified
        THEN the module-qualified class name is reported
        """
        assert classify_failure(ValueError("boom"))["error_class"] == "ValueError"

    def test_grades_a_429_as_our_fault_despite_being_a_4xx(self):
        """
        GIVEN a 429 from the GitGuardian API
        WHEN it is classified
        THEN the fault is the server's
        """
        assert classify_failure(_status_error(429))["fault"] == "server"

    def test_finds_the_status_through_a_wrapped_exception(self):
        """
        GIVEN an HTTP error re-raised as a domain exception
        WHEN it is classified
        THEN the underlying status is still found
        """
        try:
            try:
                raise _status_error(401)
            except httpx.HTTPStatusError as exc:
                raise DownstreamUnauthorizedError("401 for /incidents") from exc
        except DownstreamUnauthorizedError as exc:
            failure = classify_failure(exc)

        assert failure["upstream_status"] == 401
        assert failure["fault"] == "client"
        assert failure["error_class"] == "gg_api_core.client.DownstreamUnauthorizedError"

    def test_finds_the_status_inside_an_exception_group(self):
        """
        GIVEN an HTTP error raised inside a task group
        WHEN it is classified
        THEN the status is still found
        """
        group = ExceptionGroup("task group failed", [ValueError("unrelated"), _status_error(400)])

        failure = classify_failure(group)

        assert failure["upstream_status"] == 400
        assert failure["fault"] == "client"

    def test_respects_a_severed_context(self):
        """
        GIVEN an unrelated HTTP error severed with `raise ... from None`
        WHEN the outer exception is classified
        THEN the severed status is not attributed to it
        """
        try:
            try:
                raise _status_error(404)
            except httpx.HTTPStatusError:
                raise ValueError("bad argument") from None
        except ValueError as exc:
            failure = classify_failure(exc)

        assert "upstream_status" not in failure
        assert failure["fault"] == "server"

    @pytest.mark.parametrize(
        ("exception", "fault"),
        [
            pytest.param(
                FastMCPValidationError("Invalid arguments for tool 'get_incident'"), "client", id="bad-arguments"
            ),
            pytest.param(ToolError("The 'ignore_reason' parameter is required"), "client", id="deliberate-refusal"),
            pytest.param(MissingScopesError("assign_incident", ["incidents:write"]), "client", id="missing-scopes"),
            pytest.param(_caused_by(ToolError("Error calling tool"), KeyError("results")), "server", id="bug"),
            pytest.param(_caused_by(ToolBodyError("bad response shape"), ValueError("x")), "server", id="bad-response"),
            pytest.param(
                _caused_by(ToolError("Error calling tool"), CrossOriginRedirectError("redirected")),
                "server",
                id="cross-origin-redirect",
            ),
            pytest.param(
                _caused_by(ToolError("Error calling tool"), httpx.ReadTimeout("timed out")), "server", id="timeout"
            ),
        ],
    )
    def test_a_failure_without_an_http_status_is_the_callers_only_when_they_can_fix_it(self, exception, fault):
        """
        GIVEN a failure no API answer caused
        WHEN it is classified
        THEN invalid arguments, deliberate refusals and missing scopes are the client's fault, anything else ours
        """
        failure = classify_failure(exception)

        assert "upstream_status" not in failure
        assert failure["fault"] == fault
