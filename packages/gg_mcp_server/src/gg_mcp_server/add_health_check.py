from starlette.requests import Request
from starlette.responses import PlainTextResponse


def add_health_check(mcp):
    """Add a health check endpoint"""

    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK")
