"""Unit tests to cover __main__ script executions and module entrypoints safely.

CONCEPT:AU-ECO.mcp.fastmcp-middleware
"""

import runpy
import sys
from unittest.mock import MagicMock, patch







def test_mcp_server_module_execution():
    # CONCEPT:AU-ECO.mcp.fastmcp-middleware
    mock_mcp = MagicMock()
    mock_mcp.custom_route.return_value = lambda fn: fn
    mock_args = MagicMock()
    mock_args.transport = "stdio"
    mock_args.auth_type = "none"

    with patch(
        "agent_connector_sdk.mcp.server.create_mcp_server",
        return_value=(mock_args, mock_mcp, []),
    ):
        runpy.run_module("documentdb_mcp.mcp_server", run_name="__main__")
        assert mock_mcp.run.called
