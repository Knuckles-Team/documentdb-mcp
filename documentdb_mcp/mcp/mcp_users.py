from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_users_tools(mcp: FastMCP):
    """Register users tools.

    CONCEPT:ECO-4.1
    """

    @mcp.tool(tags={"users"})
    async def documentdb_users(
        action: str = Field(
            description="Action to perform. Must be one of: 'create_user', 'drop_user', 'update_user', 'users_info'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        username: str | None = Field(default=None, description="username"),
        password: Any | None = Field(default=None, description="password"),
        roles: Any | None = Field(default=None, description="roles"),
        client=Depends(get_client),
    ) -> dict:
        # CONCEPT:ECO-4.1
        """Manage users operations.

        Actions:
          - 'create_user': Call create_user
          - 'drop_user': Call drop_user
          - 'update_user': Call update_user
          - 'users_info': Call users_info
        """
        kwargs: dict[str, Any]
        if action == "create_user":
            kwargs = {
                "database_name": database_name,
                "username": username,
                "password": password,
                "roles": roles,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.create_user(**kwargs)
        if action == "drop_user":
            kwargs = {
                "database_name": database_name,
                "username": username,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.drop_user(**kwargs)
        if action == "update_user":
            kwargs = {
                "database_name": database_name,
                "username": username,
                "password": password,
                "roles": roles,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.update_user(**kwargs)
        if action == "users_info":
            kwargs = {
                "database_name": database_name,
                "username": username,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.users_info(**kwargs)
        raise ValueError(
            f"Unknown action: {action}. Must be one of: create_user', 'drop_user', 'update_user', 'users_info"
        )
