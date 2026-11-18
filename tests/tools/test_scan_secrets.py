import pytest
from pydantic import ValidationError

from gg_api_core.tools.scan_secret import ScanSecretsParams


class TestScanSecrets:
    """Tests for the scan_secrets tool."""

    @pytest.mark.asyncio
    async def test_scan_secrets_invalid_document_format(self, mock_gitguardian_client):
        """
        GIVEN: A document with invalid format
        WHEN: Attempting to scan
        THEN: The parameters refuse it, naming the missing field and the unknown one
        """
        with pytest.raises(ValidationError) as excinfo:
            ScanSecretsParams(documents=[{"invalid_key": "value"}])

        assert "document" in str(excinfo.value)
        assert "invalid_key" in str(excinfo.value)
