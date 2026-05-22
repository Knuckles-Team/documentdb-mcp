"""Tests for base API client helpers in documentdb_mcp/api/api_client_base.py.

CONCEPT:ECO-4.1
"""

from documentdb_mcp.api.api_client_base import parse_json_arg, serialize_oid


class ObjectId:
    def __init__(self, val):
        # CONCEPT:ECO-4.1
        self.val = val

    def __str__(self):
        # CONCEPT:ECO-4.1
        return self.val


def test_parse_json_arg():
    """Test parse_json_arg function.

    CONCEPT:ECO-4.1
    """
    # Valid JSON string
    assert parse_json_arg('{"a": 1, "b": "test"}') == {"a": 1, "b": "test"}
    # Invalid JSON string
    assert parse_json_arg("{invalid_json}") == "{invalid_json}"
    # Non-string arg
    assert parse_json_arg(123) == 123
    assert parse_json_arg({"x": 1}) == {"x": 1}
    assert parse_json_arg([1, 2]) == [1, 2]


def test_serialize_oid():
    # Primitive types
    # CONCEPT:ECO-4.1
    assert serialize_oid(123) == 123
    assert serialize_oid("test") == "test"
    assert serialize_oid(None) is None

    # Mock ObjectId
    oid = ObjectId("507f1f77bcf86cd799439011")
    assert serialize_oid(oid) == "507f1f77bcf86cd799439011"

    # Recursive dictionary
    data_dict = {"id": oid, "name": "test", "nested": {"sub_id": oid}}
    expected_dict = {
        "id": "507f1f77bcf86cd799439011",
        "name": "test",
        "nested": {"sub_id": "507f1f77bcf86cd799439011"},
    }
    assert serialize_oid(data_dict) == expected_dict

    # Recursive list
    data_list = [oid, "test", [oid]]
    expected_list = ["507f1f77bcf86cd799439011", "test", ["507f1f77bcf86cd799439011"]]
    assert serialize_oid(data_list) == expected_list
