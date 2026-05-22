"""Analysis client tests for DocumentDBApi.

CONCEPT:ECO-4.1
CONCEPT:OS-5.4
CONCEPT:OS-5.1
CONCEPT:OS-5.3
CONCEPT:ORCH-1.4
CONCEPT:OS-5.2
"""

from unittest.mock import MagicMock
import pytest
from pymongo.errors import PyMongoError
from documentdb_mcp.api_client import DocumentDBApi
from tests.test_api_base import ObjectId as MockObjectId


def test_distinct(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    col_mock.distinct.return_value = ["val1", "val2"]
    assert api_client.distinct("db1", "col1", "field", {"a": 1}) == ["val1", "val2"]
    col_mock.distinct.assert_called_with("field", {"a": 1})

    # Exception
    col_mock.distinct.side_effect = PyMongoError("Err")
    assert (
        "Error getting distinct values"
        in api_client.distinct("db1", "col1", "field", {})[0]
    )


def test_aggregate(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    cursor_mock = MagicMock()
    col_mock.aggregate.return_value = cursor_mock
    oid = MockObjectId("507f1f77bcf86cd799439011")
    cursor_mock.__iter__.return_value = [{"_id": oid, "count": 5}]

    assert api_client.aggregate("db1", "col1", [{"$match": {"a": 1}}]) == [
        {"_id": "507f1f77bcf86cd799439011", "count": 5}
    ]
    col_mock.aggregate.assert_called_with([{"$match": {"a": 1}}])

    # Exception
    col_mock.aggregate.side_effect = PyMongoError("Err")
    assert "error" in api_client.aggregate("db1", "col1", [])[0]
