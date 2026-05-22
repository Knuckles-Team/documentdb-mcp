"""Tests for auth, package init loading, health check custom routes, and command line arg routing.

CONCEPT:ECO-4.1
"""

import importlib
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# Pre-emptively mock agent_utilities to prevent tree_sitter_javascript import errors
mock_agent_utils = MagicMock()
mock_agent_utils.load_identity.return_value = {"name": "documentdb-mcp"}
sys.modules["agent_utilities"] = mock_agent_utils

import pytest
from starlette.responses import JSONResponse

import documentdb_mcp
from documentdb_mcp.agent_server import agent_server
from documentdb_mcp.auth import get_client
from documentdb_mcp.mcp_server import get_mcp_instance, mcp_server

# --- Init & Dynamic Attribute Tests ---


def test_package_init_attributes():
    """Verify package init attributes.

    CONCEPT:ECO-4.1
    """
    # Verify presence of standard module attributes
    assert hasattr(documentdb_mcp, "__getattr__")
    assert hasattr(documentdb_mcp, "__dir__")

    # Test dir list compilation
    package_dir = dir(documentdb_mcp)
    assert "__getattr__" in package_dir
    assert "CORE_MODULES" in package_dir


def test_package_getattr_availability():
    # Test MCP availability flag lookup
    # CONCEPT:ECO-4.1
    with patch("documentdb_mcp._import_module_safely") as mock_import:
        mock_import.return_value = MagicMock()
        mcp_avail = documentdb_mcp._MCP_AVAILABLE
        assert mcp_avail is True

        # Test ImportError safety check
        mock_import.return_value = None
        mcp_avail_none = documentdb_mcp._MCP_AVAILABLE
        assert mcp_avail_none is False

    # Test Agent availability flag lookup
    with patch("documentdb_mcp._import_module_safely") as mock_import:
        mock_import.return_value = MagicMock()
        agent_avail = documentdb_mcp._AGENT_AVAILABLE
        assert agent_avail is True

        # Test ImportError safety check
        mock_import.return_value = None
        agent_avail_none = documentdb_mcp._AGENT_AVAILABLE
        assert agent_avail_none is False

    # Test AttributeError on unknown attributes
    with pytest.raises(AttributeError):
        _ = documentdb_mcp.some_non_existent_attribute_name


def test_import_module_safely_real():
    # CONCEPT:ECO-4.1
    from documentdb_mcp import _import_module_safely

    # Existing module
    assert _import_module_safely("json") is not None
    # Non-existent module
    assert _import_module_safely("some_non_existent_crazy_module_name") is None


def test_empty_optional_modules():
    # CONCEPT:ECO-4.1
    with patch("documentdb_mcp.OPTIONAL_MODULES", {}):
        assert documentdb_mcp._MCP_AVAILABLE is False
        assert documentdb_mcp._AGENT_AVAILABLE is False


def test_dynamic_getattr_success():
    # CONCEPT:ECO-4.1
    with patch.dict("documentdb_mcp._loaded_optional_modules", {}, clear=True):
        val = documentdb_mcp.agent_server
        assert val is not None


# --- Auth Module Fallback Tests ---


def test_get_client_uri_scenarios():
    # CONCEPT:ECO-4.1
    with patch("pymongo.MongoClient") as mock_mongo:
        # Scenario 1: MONGODB_URI is specified
        with patch.dict(
            os.environ, {"MONGODB_URI": "mongodb://user:pass@remote:27017/"}
        ):
            client = get_client()
            assert client is not None
            mock_mongo.assert_called_with("mongodb://user:pass@remote:27017/")

        # Scenario 2: MONGODB_URI is not specified, check host/port construction
        with patch.dict(os.environ, {}, clear=True):
            # Check default localhost:27017 fallback
            client = get_client()
            assert client is not None
            mock_mongo.assert_called_with("mongodb://localhost:27017/")

            # Check explicit host and port env fallback
            with patch.dict(
                os.environ, {"MONGODB_HOST": "db-server", "MONGODB_PORT": "27018"}
            ):
                client = get_client()
                assert client is not None
                mock_mongo.assert_called_with("mongodb://db-server:27018/")


# --- Health Route Custom Endpoint Tests ---


@pytest.mark.asyncio
async def test_health_check_endpoint():
    # Capture the decorated health_check function
    health_fn = None

    def mock_custom_route(path, methods):
        def decorator(fn):
            # CONCEPT:ECO-4.1
            nonlocal health_fn
            if path == "/health":
                health_fn = fn
            return fn

        return decorator

    with patch("fastmcp.FastMCP.custom_route", side_effect=mock_custom_route):
        with patch("documentdb_mcp.mcp_server.get_client", return_value=MagicMock()):
            get_mcp_instance()

    assert health_fn is not None
    mock_request = MagicMock()
    response = await health_fn(mock_request)
    assert isinstance(response, JSONResponse)
    assert response.body == b'{"status":"OK"}'


# --- CLI Transport and Main Executable Option Tests ---


def test_mcp_server_cli_routing():
    # We will test call routing inside mcp_server() for all transport branches
    # CONCEPT:ECO-4.1
    mock_mcp = MagicMock()
    mock_args = MagicMock()
    mock_args.auth_type = "none"

    with patch("documentdb_mcp.mcp_server.get_mcp_instance") as mock_inst:
        mock_inst.return_value = (mock_mcp, mock_args, [])
        with patch("sys.argv", ["mcp_server.py"]):
            # 1. Transport stdio
            mock_args.transport = "stdio"
            mcp_server()
            mock_mcp.run.assert_called_with(transport="stdio")

            # 2. Transport streamable-http
            mock_args.transport = "streamable-http"
            mock_args.host = "1.2.3.4"
            mock_args.port = 1234
            mcp_server()
            mock_mcp.run.assert_called_with(
                transport="streamable-http", host="1.2.3.4", port=1234
            )

            # 3. Transport sse
            mock_args.transport = "sse"
            mock_args.host = "1.2.3.4"
            mock_args.port = 1234
            mcp_server()
            mock_mcp.run.assert_called_with(transport="sse", host="1.2.3.4", port=1234)

            # 4. Invalid Transport (raises SystemExit)
            mock_args.transport = "invalid-transport-type"
            with pytest.raises(SystemExit) as exc_info:
                mcp_server()
            assert exc_info.value.code == 1


def test_agent_server_debug_mode():
    # Test setting level to debug in agent_server()
    # CONCEPT:ECO-4.1
    mock_args = MagicMock()
    mock_args.mcp_url = "http://localhost:8000"
    mock_args.mcp_config = "mcp_config.json"
    mock_args.host = "localhost"
    mock_args.port = 8000
    mock_args.provider = "openai"
    mock_args.model_id = "gpt-4"
    mock_args.base_url = None
    mock_args.api_key = None
    mock_args.custom_skills_directory = None
    mock_args.web = False
    mock_args.otel = False
    mock_args.otel_endpoint = None
    mock_args.otel_headers = None
    mock_args.otel_public_key = None
    mock_args.otel_secret_key = None
    mock_args.otel_protocol = None
    mock_args.debug = True

    mock_parser = MagicMock()
    mock_parser.parse_args.return_value = mock_args

    with (
        patch("agent_utilities.initialize_workspace"),
        patch("agent_utilities.load_identity", return_value={"name": "test-agent"}),
        patch("agent_utilities.create_agent_parser", return_value=mock_parser),
        patch("agent_utilities.create_agent_server") as mock_server_create,
        patch("logging.getLogger") as mock_get_logger,
    ):
        with patch("sys.argv", ["agent_server.py"]):
            agent_server()

            # Verify that logging setLevel to DEBUG was invoked
            mock_get_logger.return_value.setLevel.assert_called_with(logging.DEBUG)
            # Verify server creation call was completed
            assert mock_server_create.called


def test_direct_getattr_call():
    # Force a direct call to __getattr__ to bypass globals lookup order and cover line 69
    # CONCEPT:ECO-4.1
    mock_module = MagicMock()
    mock_module.some_attribute = "test_value"
    with patch.dict(
        "documentdb_mcp._loaded_optional_modules",
        {"documentdb_mcp.agent_server": mock_module},
    ):
        val = documentdb_mcp.__getattr__("some_attribute")
        assert val == "test_value"


def test_requests_import_error():
    # Hide requests from sys.modules during reload to trigger the ImportError catch block
    real_import = __import__

    def mock_import(name, *args, **kwargs):
        # CONCEPT:ECO-4.1
        if name.startswith("requests"):
            raise ImportError("Mocked import error for requests")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        res = importlib.reload(sys.modules["documentdb_mcp.mcp_server"])
        assert res is not None
