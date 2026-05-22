from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_collections_tools(mcp: FastMCP):
    """Register collections tools.

    CONCEPT:ECO-4.1
    """

    @mcp.tool(tags={"collections"})
    async def documentdb_collections(
        action: str = Field(
            description="Action to perform. Must be one of: 'list_collections', 'create_collection', 'drop_collection', 'create_database', 'drop_database', 'rename_collection'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        collection_name: str | None = Field(
            default=None, description="collection name"
        ),
        initial_collection: str | None = Field(
            default=None, description="initial collection"
        ),
        old_name: str | None = Field(default=None, description="old name"),
        new_name: str | None = Field(default=None, description="new name"),
        client=Depends(get_client),
    ) -> dict:
        # CONCEPT:ECO-4.1
        """Manage collections operations.

        Actions:
          - 'list_collections': Call list_collections
          - 'create_collection': Call create_collection
          - 'drop_collection': Call drop_collection
          - 'create_database': Call create_database
          - 'drop_database': Call drop_database
          - 'rename_collection': Call rename_collection
        """
        kwargs: dict[str, Any]
        if action == "list_collections":
            kwargs = {"database_name": database_name}
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.list_collections(**kwargs)
        if action == "create_collection":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.create_collection(**kwargs)
        if action == "drop_collection":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.drop_collection(**kwargs)
        if action == "create_database":
            kwargs = {
                "database_name": database_name,
                "initial_collection": initial_collection,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.create_database(**kwargs)
        if action == "drop_database":
            kwargs = {"database_name": database_name}
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.drop_database(**kwargs)
        if action == "rename_collection":
            kwargs = {
                "database_name": database_name,
                "old_name": old_name,
                "new_name": new_name,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.rename_collection(**kwargs)
        raise ValueError(
            f"Unknown action: {action}. Must be one of: list_collections', 'create_collection', 'drop_collection', 'create_database', 'drop_database', 'rename_collection"
        )
