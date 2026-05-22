from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_system_tools(mcp: FastMCP):
    """Register system tools.

    CONCEPT:ECO-4.1
    """

    @mcp.tool(tags={"system"})
    async def documentdb_system(
        action: str = Field(
            description="Action to perform. Must be one of: 'binary_version', 'list_databases', 'run_command'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        command: dict[str, Any] | None = Field(default=None, description="command"),
        client=Depends(get_client),
    ) -> dict:
        # CONCEPT:ECO-4.1
        """Manage system operations.

        Actions:
          - 'binary_version': Call binary_version
          - 'list_databases': Call list_databases
          - 'run_command': Call run_command
        """
        kwargs: dict[str, Any]
        if action == "binary_version":
            kwargs = {}
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.binary_version(**kwargs)
        if action == "list_databases":
            kwargs = {}
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.list_databases(**kwargs)
        if action == "run_command":
            kwargs = {
                "database_name": database_name,
                "command": command,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.run_command(**kwargs)
        raise ValueError(
            f"Unknown action: {action}. Must be one of: binary_version', 'list_databases', 'run_command"
        )
