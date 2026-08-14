from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def _entitled(namespace: str, names: list[str]) -> list[str]:
    """Filter ``names`` to what the calling identity may reach.

    Routes the set through agent-utilities' shared identity-scoped resolver
    (CONCEPT:AU-OS.identity.identity-scoped-resource-autoload): a caller's
    Okta/Keycloak groups decide which resources they see by default. The
    ambient ``SYSTEM_ACTOR`` (unauthenticated/local) holds ``admin`` → sees
    all, so behaviour is unchanged until a real identity scopes it down.
    Degrades to the full set if agent-utilities predates the resolver.
    """
    try:
        from agent_utilities.security.entitlements import (
            identity_scoped_resources,
        )
    except Exception:
        return list(names)
    return list(identity_scoped_resources(namespace, names))


def register_system_tools(mcp: FastMCP):
    """Register system tools.

    CONCEPT:AU-ECO.mcp.fastmcp-middleware
    """

    @mcp.tool(tags={"system"})
    async def documentdb_system(
        action: str = Field(
            description="Action to perform. Must be one of: 'binary_version', 'list_databases', 'run_command'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        command: dict[str, Any] | None = Field(default=None, description="command"),
        client=Depends(get_client),
    ) -> dict | list[str]:
        # CONCEPT:AU-ECO.mcp.fastmcp-middleware
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
            databases = client.list_databases(**kwargs)
            return _entitled("db", databases)
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
