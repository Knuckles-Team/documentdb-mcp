"""Tests for mcp_server.py - MCP server tool registration.

CONCEPT:AU-ECO.mcp.fastmcp-middleware
"""

from unittest.mock import MagicMock, patch


class TestToolRegistration:
    def test_tools_registered(self):
        """The actual SDK-composed server retains the existing API and KG tools."""
        import asyncio

        from fastmcp import Client
        from documentdb_mcp.mcp_server import get_mcp_instance

        async def capture():
            server, _, _ = get_mcp_instance(command_args=["--transport", "stdio", "--auth-type", "none"])
            async with Client(server) as client:
                return {tool.name for tool in await client.list_tools()}

        names = asyncio.run(capture())
        assert len(names) == 30
        assert {"documentdb_find", "documentdb_ingest_documents"} <= names


class TestGetMcpInstance:
    def test_get_mcp_instance(self):
        """Keep the legacy server/args/middleware startup tuple."""
        from documentdb_mcp.mcp_server import get_mcp_instance

        server = MagicMock()
        middleware = MagicMock()
        server.middleware = [middleware]
        arguments = MagicMock()
        with patch("documentdb_mcp.mcp_server.build_server", return_value=(arguments, server)):
            actual_server, actual_args, actual_middlewares = get_mcp_instance()
        assert actual_server is server
        assert actual_args is arguments
        assert actual_middlewares == [middleware]


class TestVersion:
    def test_version_defined(self):
        # CONCEPT:AU-ECO.mcp.fastmcp-middleware
        from documentdb_mcp.mcp_server import __version__

        assert __version__ is not None
        assert isinstance(__version__, str)
