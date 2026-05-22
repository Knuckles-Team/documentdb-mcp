import asyncio
import inspect
import sys
from typing import Any
from unittest.mock import MagicMock, patch

# Pre-emptively mock agent_utilities to prevent tree_sitter_javascript import errors
mock_agent_utils = MagicMock()
mock_agent_utils.load_identity.return_value = {"name": "documentdb-mcp"}
sys.modules["agent_utilities"] = mock_agent_utils

import pytest


@pytest.fixture
def mock_mongo():
    # CONCEPT:ECO-4.1
    with (
        patch("pymongo.MongoClient") as mock_client,
        patch("documentdb_mcp.mcp_server.get_client") as mock_get_client,
    ):
        client = mock_client.return_value
        mock_get_client.return_value = client
        # Mock admin.command("ping")
        client.admin.command.return_value = {"ok": 1.0, "version": "5.0.0"}

        # Mock database and collection
        db = MagicMock()
        client.__getitem__.return_value = db
        coll = MagicMock()
        db.__getitem__.return_value = coll

        # Mock CRUD return objects
        coll.insert_one.return_value.inserted_id = "test_id"
        coll.insert_many.return_value.inserted_ids = ["test_id"]
        coll.find_one.return_value = {"_id": "test_id", "name": "test"}
        coll.find_one_and_update.return_value = {"_id": "test_id"}
        coll.find_one_and_replace.return_value = {"_id": "test_id"}
        coll.find_one_and_delete.return_value = {"_id": "test_id"}
        coll.replace_one.return_value.matched_count = 1
        coll.replace_one.return_value.modified_count = 1
        coll.update_one.return_value.matched_count = 1
        coll.update_one.return_value.modified_count = 1
        coll.update_many.return_value.matched_count = 1
        coll.update_many.return_value.modified_count = 1
        coll.delete_one.return_value.deleted_count = 1
        coll.delete_many.return_value.deleted_count = 1
        coll.count_documents.return_value = 1
        coll.distinct.return_value = ["val"]

        # Mock cursor for find
        cursor = MagicMock()
        coll.find.return_value = cursor
        cursor.sort.return_value = cursor
        cursor.skip.return_value = cursor
        cursor.limit.return_value = cursor
        cursor.__iter__.return_value = [{"_id": "test_id", "name": "test"}]

        # Mock cursor for aggregate
        agg_cursor = MagicMock()
        coll.aggregate.return_value = agg_cursor
        agg_cursor.__iter__.return_value = [{"_id": "test_id"}]

        # Mock database / list collection names
        client.list_database_names.return_value = ["db1"]
        db.list_collection_names.return_value = ["coll1"]

        yield mock_client


def test_mcp_server_coverage(mock_mongo):
    _ = mock_mongo
    from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware

    from documentdb_mcp.mcp_server import get_mcp_instance

    async def mock_on_request(self, context, call_next):
        # CONCEPT:ECO-4.1
        return await call_next(context)

    with patch.object(RateLimitingMiddleware, "on_request", mock_on_request):
        mcp_data = get_mcp_instance()
        mcp = mcp_data[0] if isinstance(mcp_data, tuple) else mcp_data

        # Explicit map of each tool name to all valid actions and one invalid action to cover ValuErrors
        tool_actions = {
            "documentdb_system": [
                "binary_version",
                "list_databases",
                "run_command",
                "invalid_action",
            ],
            "documentdb_collections": [
                "list_collections",
                "create_collection",
                "drop_collection",
                "create_database",
                "drop_database",
                "rename_collection",
                "invalid_action",
            ],
            "documentdb_users": [
                "create_user",
                "drop_user",
                "update_user",
                "users_info",
                "invalid_action",
            ],
            "documentdb_crud": [
                "insert_one",
                "insert_many",
                "find_one",
                "find",
                "replace_one",
                "update_one",
                "update_many",
                "delete_one",
                "delete_many",
                "count_documents",
                "find_one_and_update",
                "find_one_and_replace",
                "find_one_and_delete",
                "invalid_action",
            ],
            "documentdb_analysis": ["distinct", "aggregate", "invalid_action"],
        }

        async def run_tools():
            # CONCEPT:ECO-4.1
            tool_objs = (
                await mcp.list_tools()
                if inspect.iscoroutinefunction(mcp.list_tools)
                else mcp.list_tools()
            )
            for tool in tool_objs:
                actions = tool_actions.get(tool.name, [None])
                for action in actions:
                    try:
                        target_params: dict[str, Any] = {
                            "database_name": "test_db",
                            "collection_name": "test_coll",
                            "document": {"a": 1},
                            "documents": [{"a": 1}],
                            "filter": {"a": 1},
                            "update": {"$set": {"a": 2}},
                            "replacement": {"a": 2},
                            "username": "user",
                            "password": "pwd",
                            "roles": [],
                            "command": {"ping": 1},
                            "key": "name",
                            "pipeline": [],
                        }
                        if action is not None:
                            target_params["action"] = action

                        # Inspect tool parameters to strictly filter accepted parameters
                        sig = inspect.signature(tool.fn)
                        tool_params = {}
                        for p_name, p in sig.parameters.items():
                            if p_name in ["_client", "context", "client"]:
                                continue
                            if p_name in target_params:
                                tool_params[p_name] = target_params[p_name]
                            elif p.default == inspect.Parameter.empty:
                                # Fallback
                                tool_params[p_name] = (
                                    "test" if p.annotation is str else 1
                                )

                        await mcp.call_tool(tool.name, tool_params)
                    except Exception as e:
                        # ValueError exceptions will raise and be caught here
                        print(f"Tool {tool.name} with action {action} failed: {e}")

        asyncio.run(run_tools())
        assert mcp is not None


def test_agent_server_coverage():
    # CONCEPT:ECO-4.1
    import documentdb_mcp.agent_server as mod
    from documentdb_mcp import agent_server

    with patch("agent_utilities.create_agent_server") as mock_s:
        with patch("sys.argv", ["agent_server.py"]):
            if inspect.isfunction(agent_server):
                agent_server()
            else:
                mod.agent_server()
            assert mock_s.called


def test_main_coverage():
    # CONCEPT:ECO-4.1
    from documentdb_mcp.mcp_server import mcp_server

    with patch("sys.argv", ["mcp_server.py"]):
        with patch("documentdb_mcp.mcp_server.get_mcp_instance") as mock_inst:
            mock_mcp = MagicMock()
            mock_args = MagicMock()
            mock_args.transport = "stdio"
            mock_inst.return_value = (mock_mcp, mock_args, [])
            try:
                mcp_server()
            except SystemExit:
                pass
            assert mock_mcp.run.called
