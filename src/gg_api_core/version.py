"""Application release metadata."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version


def resolve_app_version() -> str | None:
    """Return the installed ``gg-mcp-server`` release, if its metadata is available."""
    try:
        return package_version("gg-mcp-server")
    except PackageNotFoundError:
        return None


APP_VERSION = resolve_app_version()
