from importlib.metadata import PackageNotFoundError
from unittest.mock import Mock

from gg_api_core.version import resolve_app_version


class TestResolveAppVersion:
    """Tests for application release metadata lookup."""

    def test_returns_the_umbrella_distribution_version(self, monkeypatch):
        """
        GIVEN the ggmcp distribution metadata is installed
        WHEN the application version is resolved
        THEN its release number is returned
        """
        package_version = Mock(return_value="1.2.3")
        monkeypatch.setattr("gg_api_core.version.package_version", package_version)

        assert resolve_app_version() == "1.2.3"
        package_version.assert_called_once_with("ggmcp")

    def test_returns_none_when_distribution_metadata_is_unavailable(self, monkeypatch):
        """
        GIVEN the ggmcp distribution metadata is unavailable
        WHEN the application version is resolved
        THEN the absence is represented explicitly
        """

        def missing_distribution(distribution: str) -> str:
            raise PackageNotFoundError(distribution)

        monkeypatch.setattr("gg_api_core.version.package_version", missing_distribution)

        assert resolve_app_version() is None
