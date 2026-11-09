import pytest

from gg_api_core.tools.scan_secret import ScanSecretsParams, scan_secrets


class TestScanSecrets:
    """Tests for the scan_secrets tool."""

    @pytest.mark.asyncio
    async def test_scan_secrets_invalid_document_format(self, mock_gitguardian_client):
        """
        GIVEN: A document with invalid format
        WHEN: Attempting to scan
        THEN: A ValueError is raised
        """
        # Call the function with invalid document format
        with pytest.raises(ValueError) as excinfo:
            await scan_secrets(ScanSecretsParams(documents=[{"invalid_key": "value"}]))

        # Verify error message
        assert "must be a dictionary with a 'document' field" in str(excinfo.value)
