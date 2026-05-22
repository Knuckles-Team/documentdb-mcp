"""System and Collections client tests for DocumentDBApi.

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


def test_binary_version(api_client, mock_client):
    # Success
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    mock_client.admin.command.return_value = {"version": "5.0.4"}
    assert api_client.binary_version() == "5.0.4"

    # Error fallback
    # CONCEPT:OS-5.1
    mock_client.admin.command.side_effect = Exception("Connection lost")
    assert "Error: Connection lost" in api_client.binary_version()


def test_list_databases(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    mock_client.list_database_names.return_value = ["admin", "local", "test"]
    assert api_client.list_databases() == ["admin", "local", "test"]


def test_run_command(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    oid = MockObjectId("507f1f77bcf86cd799439011")
    db_mock.command.return_value = {"ok": 1.0, "_id": oid}

    assert api_client.run_command("test_db", {"ping": 1}) == {
        "ok": 1.0,
        "_id": "507f1f77bcf86cd799439011",
    }
    db_mock.command.assert_called_with({"ping": 1})


def test_create_database(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    assert (
        "Collection 'init_col' created in database 'new_db'"
        in api_client.create_database("new_db", "init_col")
    )
    db_mock.create_collection.assert_called_with("init_col")

    # Exception
    db_mock.create_collection.side_effect = PyMongoError("Already exists")
    assert "Error creating collection" in api_client.create_database(
        "new_db", "init_col"
    )


def test_drop_database(api_client, mock_client):
    # Success
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    assert "Database 'temp_db' dropped" in api_client.drop_database("temp_db")
    mock_client.drop_database.assert_called_with("temp_db")

    # Exception
    mock_client.drop_database.side_effect = PyMongoError("Err")
    assert "Error dropping database" in api_client.drop_database("temp_db")


def test_list_collections(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    db_mock.list_collection_names.return_value = ["c1", "c2"]
    assert api_client.list_collections("db1") == ["c1", "c2"]


def test_create_collection(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    assert (
        "Collection 'c1' created in database 'db1'"
        in api_client.create_collection("db1", "c1")
    )
    db_mock.create_collection.assert_called_with("c1")

    # Exception
    db_mock.create_collection.side_effect = PyMongoError("Err")
    assert "Error creating collection" in api_client.create_collection("db1", "c1")


def test_drop_collection(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    assert (
        "Collection 'c1' dropped from database 'db1'"
        in api_client.drop_collection("db1", "c1")
    )
    db_mock.drop_collection.assert_called_with("c1")

    # Exception
    db_mock.drop_collection.side_effect = PyMongoError("Err")
    assert "Error dropping collection" in api_client.drop_collection("db1", "c1")


def test_rename_collection(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    assert (
        "Collection 'old' renamed to 'new'"
        in api_client.rename_collection("db1", "old", "new")
    )
    col_mock.rename.assert_called_with("new")

    # Exception
    col_mock.rename.side_effect = PyMongoError("Err")
    assert "Error renaming collection" in api_client.rename_collection(
        "db1", "old", "new"
    )
