"""Shared Pytest fixtures for documentdb-mcp.

Inherits or implements: CONCEPT:AU-ECO.mcp.fastmcp-middleware
"""

from unittest.mock import MagicMock
import pytest
from documentdb_mcp.api_client import DocumentDBApi


@pytest.fixture
def mock_client():
    """Mock MongoClient instance for testing.

    CONCEPT:AU-ECO.mcp.fastmcp-middleware
    """
    client = MagicMock()
    # Mock admin command return
    client.admin.command.return_value = {"version": "6.0.0"}
    # Mock list_database_names
    client.list_database_names.return_value = ["test_db"]
    return client


@pytest.fixture
def api_client(mock_client):
    """Authenticated DocumentDBApi instance for testing.

    CONCEPT:AU-ECO.mcp.fastmcp-middleware
    """
    return DocumentDBApi(client=mock_client)


def pytest_configure(config):
    """Register the spec marker that binds a test to a requirement row."""
    config.addinivalue_line(
        "markers", "spec(id): Binds a test to a requirement row of a spec."
    )
