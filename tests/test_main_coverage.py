"""Unit tests to cover __main__ script executions and module entrypoints safely.

CONCEPT:ECO-4.1
"""

import runpy
import sys
from unittest.mock import MagicMock, patch

# Pre-emptively mock agent_utilities to prevent tree_sitter_javascript import errors
mock_agent_utils = MagicMock()
mock_agent_utils.load_identity.return_value = {"name": "documentdb-mcp"}
sys.modules["agent_utilities"] = mock_agent_utils


def test_main_module_execution():
    """Verify that __main__ executes the agent server command correctly.

    CONCEPT:ECO-4.1
    """
    with patch("documentdb_mcp.agent_server.agent_server") as mock_agent:
        runpy.run_module("documentdb_mcp.__main__", run_name="__main__")
        assert mock_agent.called


def test_agent_server_module_execution():
    # CONCEPT:ECO-4.1
    mock_parser = MagicMock()
    mock_args = MagicMock()
    mock_args.debug = False
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
    mock_parser.parse_args.return_value = mock_args

    with (
        patch("agent_utilities.initialize_workspace"),
        patch("agent_utilities.load_identity", return_value={"name": "test-agent"}),
        patch("agent_utilities.create_agent_parser", return_value=mock_parser),
        patch("agent_utilities.create_agent_server") as mock_server_create,
    ):
        runpy.run_module("documentdb_mcp.agent_server", run_name="__main__")
        assert mock_server_create.called


def test_mcp_server_module_execution():
    # CONCEPT:ECO-4.1
    mock_mcp = MagicMock()
    mock_mcp.custom_route.return_value = lambda fn: fn
    mock_args = MagicMock()
    mock_args.transport = "stdio"
    mock_args.auth_type = "none"

    with patch(
        "agent_utilities.mcp_utilities.create_mcp_server",
        return_value=(mock_args, mock_mcp, []),
    ):
        runpy.run_module("documentdb_mcp.mcp_server", run_name="__main__")
        assert mock_mcp.run.called
