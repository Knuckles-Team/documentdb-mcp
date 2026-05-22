"""CRUD client tests for DocumentDBApi.

CONCEPT:ECO-4.1
CONCEPT:OS-5.4
CONCEPT:OS-5.1
CONCEPT:OS-5.3
CONCEPT:ORCH-1.4
CONCEPT:OS-5.2
"""

from unittest.mock import MagicMock
import pymongo
import pytest
from pymongo.errors import PyMongoError
from documentdb_mcp.api_client import DocumentDBApi
from tests.test_api_base import ObjectId as MockObjectId


def test_insert_one(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.inserted_id = MockObjectId("507f1f77bcf86cd799439011")
    col_mock.insert_one.return_value = res_mock
    assert (
        api_client.insert_one("test_db", "test_col", {"name": "test"})
        == "507f1f77bcf86cd799439011"
    )

    # Exception
    col_mock.insert_one.side_effect = PyMongoError("Mock insert error")
    assert "Error inserting document" in api_client.insert_one(
        "test_db", "test_col", {"name": "test"}
    )


def test_insert_many(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.inserted_ids = [
        MockObjectId("507f1f77bcf86cd799439011"),
        MockObjectId("507f1f77bcf86cd799439012"),
    ]
    col_mock.insert_many.return_value = res_mock
    assert api_client.insert_many("test_db", "test_col", [{"a": 1}, {"b": 2}]) == [
        "507f1f77bcf86cd799439011",
        "507f1f77bcf86cd799439012",
    ]

    # Exception
    col_mock.insert_many.side_effect = PyMongoError("Mock insert_many error")
    assert (
        "Error inserting documents"
        in api_client.insert_many("test_db", "test_col", [{"a": 1}])[0]
    )


def test_find_one(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success (found)
    oid = MockObjectId("507f1f77bcf86cd799439011")
    col_mock.find_one.return_value = {"_id": oid, "name": "test"}
    assert api_client.find_one("test_db", "test_col", {"name": "test"}) == {
        "_id": "507f1f77bcf86cd799439011",
        "name": "test",
    }

    # Success (not found)
    col_mock.find_one.return_value = None
    assert api_client.find_one("test_db", "test_col", {"name": "test"}) is None

    # Exception
    col_mock.find_one.side_effect = PyMongoError("Mock find_one error")
    assert "error" in api_client.find_one("test_db", "test_col", {"name": "test"})


def test_find(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success with skip, limit, sort
    cursor_mock = MagicMock()
    col_mock.find.return_value = cursor_mock
    cursor_mock.sort.return_value = cursor_mock
    cursor_mock.skip.return_value = cursor_mock
    cursor_mock.limit.return_value = cursor_mock

    oid = MockObjectId("507f1f77bcf86cd799439011")
    cursor_mock.__iter__.return_value = [{"_id": oid, "val": 100}]

    res = api_client.find(
        "test_db", "test_col", {"val": 100}, limit=10, skip=5, sort=[("val", -1)]
    )
    assert res == [{"_id": "507f1f77bcf86cd799439011", "val": 100}]
    col_mock.find.assert_called_with({"val": 100})
    cursor_mock.sort.assert_called_with([("val", -1)])
    cursor_mock.skip.assert_called_with(5)
    cursor_mock.limit.assert_called_with(10)

    # Exception
    col_mock.find.side_effect = PyMongoError("Mock find error")
    assert "error" in api_client.find("test_db", "test_col", {})[0]


def test_replace_one(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.matched_count = 1
    res_mock.modified_count = 1
    col_mock.replace_one.return_value = res_mock
    assert "Matched: 1, Modified: 1" in api_client.replace_one(
        "test_db", "test_col", {"_id": "1"}, {"a": 2}
    )

    # Exception
    col_mock.replace_one.side_effect = PyMongoError("Mock replace_one error")
    assert "Error replacing document" in api_client.replace_one(
        "test_db", "test_col", {}, {}
    )


def test_update_one(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.matched_count = 2
    res_mock.modified_count = 1
    col_mock.update_one.return_value = res_mock
    assert "Matched: 2, Modified: 1" in api_client.update_one(
        "test_db", "test_col", {"a": 1}, {"$set": {"a": 2}}
    )

    # Exception
    col_mock.update_one.side_effect = PyMongoError("Mock update_one error")
    assert "Error updating document" in api_client.update_one(
        "test_db", "test_col", {}, {}
    )


def test_update_many(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.matched_count = 5
    res_mock.modified_count = 4
    col_mock.update_many.return_value = res_mock
    assert "Matched: 5, Modified: 4" in api_client.update_many(
        "test_db", "test_col", {"a": 1}, {"$set": {"a": 2}}
    )

    # Exception
    col_mock.update_many.side_effect = PyMongoError("Mock update_many error")
    assert "Error updating documents" in api_client.update_many(
        "test_db", "test_col", {}, {}
    )


def test_delete_one(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.deleted_count = 1
    col_mock.delete_one.return_value = res_mock
    assert "Deleted: 1" in api_client.delete_one("test_db", "test_col", {"a": 1})

    # Exception
    col_mock.delete_one.side_effect = PyMongoError("Mock delete_one error")
    assert "Error deleting document" in api_client.delete_one("test_db", "test_col", {})


def test_delete_many(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    res_mock = MagicMock()
    res_mock.deleted_count = 10
    col_mock.delete_many.return_value = res_mock
    assert "Deleted: 10" in api_client.delete_many("test_db", "test_col", {"a": 1})

    # Exception
    col_mock.delete_many.side_effect = PyMongoError("Mock delete_many error")
    assert "Error deleting documents" in api_client.delete_many(
        "test_db", "test_col", {}
    )


def test_count_documents(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    col_mock.count_documents.return_value = 42
    assert api_client.count_documents("test_db", "test_col", {"a": 1}) == 42

    # Exception
    col_mock.count_documents.side_effect = PyMongoError("Mock count error")
    assert api_client.count_documents("test_db", "test_col", {}) == -1


def test_find_one_and_update(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success return before
    oid = MockObjectId("507f1f77bcf86cd799439011")
    col_mock.find_one_and_update.return_value = {"_id": oid, "status": "old"}

    res = api_client.find_one_and_update(
        "test_db", "test_col", {"a": 1}, {"$set": {"b": 2}}, return_document="before"
    )
    assert res == {"_id": "507f1f77bcf86cd799439011", "status": "old"}
    col_mock.find_one_and_update.assert_called_with(
        {"a": 1}, {"$set": {"b": 2}}, return_document=pymongo.ReturnDocument.BEFORE
    )

    # Success return after
    api_client.find_one_and_update(
        "test_db", "test_col", {"a": 1}, {"$set": {"b": 2}}, return_document="after"
    )
    col_mock.find_one_and_update.assert_called_with(
        {"a": 1}, {"$set": {"b": 2}}, return_document=pymongo.ReturnDocument.AFTER
    )

    # None found
    col_mock.find_one_and_update.return_value = None
    assert api_client.find_one_and_update("test_db", "test_col", {}, {}) is None

    # Exception
    col_mock.find_one_and_update.side_effect = PyMongoError(
        "Mock find_one_and_update error"
    )
    assert "error" in api_client.find_one_and_update("test_db", "test_col", {}, {})


def test_find_one_and_replace(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success return before
    oid = MockObjectId("507f1f77bcf86cd799439011")
    col_mock.find_one_and_replace.return_value = {"_id": oid, "status": "old"}

    res = api_client.find_one_and_replace(
        "test_db", "test_col", {"a": 1}, {"b": 2}, return_document="before"
    )
    assert res == {"_id": "507f1f77bcf86cd799439011", "status": "old"}
    col_mock.find_one_and_replace.assert_called_with(
        {"a": 1}, {"b": 2}, return_document=pymongo.ReturnDocument.BEFORE
    )

    # Success return after
    api_client.find_one_and_replace(
        "test_db", "test_col", {"a": 1}, {"b": 2}, return_document="after"
    )
    col_mock.find_one_and_replace.assert_called_with(
        {"a": 1}, {"b": 2}, return_document=pymongo.ReturnDocument.AFTER
    )

    # None found
    col_mock.find_one_and_replace.return_value = None
    assert api_client.find_one_and_replace("test_db", "test_col", {}, {}) is None

    # Exception
    col_mock.find_one_and_replace.side_effect = PyMongoError(
        "Mock find_one_and_replace error"
    )
    assert "error" in api_client.find_one_and_replace("test_db", "test_col", {}, {})


def test_find_one_and_delete(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    col_mock = db_mock.__getitem__.return_value

    # Success
    oid = MockObjectId("507f1f77bcf86cd799439011")
    col_mock.find_one_and_delete.return_value = {"_id": oid, "deleted": True}
    assert api_client.find_one_and_delete("test_db", "test_col", {"a": 1}) == {
        "_id": "507f1f77bcf86cd799439011",
        "deleted": True,
    }

    # None found
    col_mock.find_one_and_delete.return_value = None
    assert api_client.find_one_and_delete("test_db", "test_col", {}) is None

    # Exception
    col_mock.find_one_and_delete.side_effect = PyMongoError(
        "Mock find_one_and_delete error"
    )
    assert "error" in api_client.find_one_and_delete("test_db", "test_col", {})
