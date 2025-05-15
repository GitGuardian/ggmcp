"""Utility functions and fixtures for tests."""

import json
from pathlib import Path
from typing import Any, Dict


def load_fixture(fixture_name: str) -> Dict[str, Any]:
    """Load a fixture from the fixtures directory.

    Args:
        fixture_name: Name of the fixture file (without extension)

    Returns:
        Dictionary with fixture data
    """
    fixture_path = Path(__file__).parent / "fixtures" / f"{fixture_name}.json"
    with open(fixture_path, "r") as f:
        return json.load(f)


def create_mock_response(data: Dict[str, Any], status_code: int = 200) -> Dict[str, Any]:
    """Create a standardized mock response.

    Args:
        data: Response data
        status_code: HTTP status code

    Returns:
        Dictionary with standardized response format
    """
    return {
        "data": data,
        "status_code": status_code,
        "pagination": {"total_count": len(data) if isinstance(data, list) else 1, "page": 1, "per_page": 20},
    }
