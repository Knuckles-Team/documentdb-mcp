"""Users client tests for DocumentDBApi.

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


def test_create_user(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    assert "User 'u1' created on 'db1'" in api_client.create_user(
        "db1", "u1", "p1", ["readWrite"]
    )
    db_mock.command.assert_called_with(
        "createUser", "u1", pwd="p1", roles=["readWrite"]
    )

    # Exception
    db_mock.command.side_effect = PyMongoError("Exists")
    assert "Error creating user" in api_client.create_user("db1", "u1", "p1", [])


def test_drop_user(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    assert "User 'u1' dropped from 'db1'" in api_client.drop_user("db1", "u1")
    db_mock.command.assert_called_with("dropUser", "u1")

    # Exception
    db_mock.command.side_effect = PyMongoError("Not found")
    assert "Error dropping user" in api_client.drop_user("db1", "u1")


@pytest.mark.parametrize(
    "password,roles,expected_call_args",
    [
        ("new_password", None, {"pwd": "new_password"}),
        (None, ["dbAdmin"], {"roles": ["dbAdmin"]}),
        ("new_password", ["dbAdmin"], {"pwd": "new_password", "roles": ["dbAdmin"]}),
    ],
)
def test_update_user_success(
    api_client, mock_client, password, roles, expected_call_args
):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value
    assert "User 'u1' updated on 'db1'" in api_client.update_user(
        "db1", "u1", password=password, roles=roles
    )
    db_mock.command.assert_called_with("updateUser", "u1", **expected_call_args)


def test_update_user_edge_cases(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Update neither (empty)
    assert "No updates specified." in api_client.update_user("db1", "u1")

    # Exception
    db_mock.command.side_effect = PyMongoError("Err")
    assert "Error updating user" in api_client.update_user("db1", "u1", password="pw")


def test_users_info(api_client, mock_client):
    # CONCEPT:ECO-4.1
    # CONCEPT:OS-5.4
    db_mock = mock_client.__getitem__.return_value

    # Success
    oid = MockObjectId("507f1f77bcf86cd799439011")
    db_mock.command.return_value = {"user": "u1", "_id": oid}
    assert api_client.users_info("db1", "u1") == {
        "user": "u1",
        "_id": "507f1f77bcf86cd799439011",
    }
    db_mock.command.assert_called_with("usersInfo", "u1")

    # Exception
    db_mock.command.side_effect = PyMongoError("Err")
    assert "error" in api_client.users_info("db1", "u1")
