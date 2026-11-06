"""Application release metadata."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version


def resolve_app_version() -> str | None:
    """Return the installed ``ggmcp`` release, if its metadata is available."""
    try:
        return package_version("ggmcp")
    except PackageNotFoundError:
        return None


APP_VERSION = resolve_app_version()
