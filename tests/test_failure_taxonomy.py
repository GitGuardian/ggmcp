"""Grading of tool failures into queryable fields."""

import httpx
from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.log_context import classify_failure


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

    def test_grades_a_4xx_as_the_caller_s_fault(self):
        """
        GIVEN a 400 from the GitGuardian API
        WHEN it is classified
        THEN the status is surfaced and the fault is the client's
        """
        failure = classify_failure(_status_error(400))

        assert failure["upstream_status"] == 400
        assert failure["fault"] == "client"

    def test_grades_a_5xx_as_our_fault(self):
        """
        GIVEN a 502 from the GitGuardian API
        WHEN it is classified
        THEN the fault is the server's
        """
        assert classify_failure(_status_error(502))["fault"] == "server"

    def test_grades_a_429_as_our_fault_despite_being_a_4xx(self):
        """
        GIVEN a 429 from the GitGuardian API
        WHEN it is classified
        THEN the fault is the server's
        """
        assert classify_failure(_status_error(429))["fault"] == "server"

    def test_grades_an_unexpected_exception_as_our_fault(self):
        """
        GIVEN an exception with no HTTP status anywhere in its chain
        WHEN it is classified
        THEN the fault is the server's and no status is invented
        """
        failure = classify_failure(KeyError("missing"))

        assert failure["fault"] == "server"
        assert "upstream_status" not in failure

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

    def test_surfaces_the_gitguardian_error_code(self):
        """
        GIVEN an error body carrying a machine-readable code
        WHEN it is classified
        THEN the code is surfaced as its own field
        """
        failure = classify_failure(_status_error(400, {"code": "invalid_severity"}))

        assert failure["gg_error_code"] == "invalid_severity"

    def test_ignores_the_detail_prose(self):
        """
        GIVEN an error body whose `detail` echoes the submitted document
        WHEN it is classified
        THEN no error code is emitted
        """
        failure = classify_failure(
            _status_error(400, {"detail": "Invalid document: 'aws_secret_access_key=wJalrXUtnFEMI'"})
        )

        assert "gg_error_code" not in failure
        assert "wJalrXUtnFEMI" not in str(failure)

    def test_rejects_an_over_long_code(self):
        """
        GIVEN a `code` field carrying a sentence rather than an identifier
        WHEN it is classified
        THEN it is not surfaced
        """
        failure = classify_failure(_status_error(400, {"code": "x" * 200}))

        assert "gg_error_code" not in failure

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

    def test_tolerates_a_non_json_error_body(self):
        """
        GIVEN an error body that is not JSON (a proxy's HTML error page)
        WHEN it is classified
        THEN the status is still reported and no code is invented
        """
        failure = classify_failure(_status_error(502, "<html>bad gateway</html>"))

        assert failure["upstream_status"] == 502
        assert "gg_error_code" not in failure
