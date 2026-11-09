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
