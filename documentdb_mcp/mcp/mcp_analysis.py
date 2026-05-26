from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_analysis_tools(mcp: FastMCP):
    """Register analysis tools.

    CONCEPT:ECO-4.1
    """

    @mcp.tool(tags={"analysis"})
    async def documentdb_analysis(
        action: str = Field(
            description="Action to perform. Must be one of: 'distinct', 'aggregate'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        collection_name: str | None = Field(
            default=None, description="collection name"
        ),
        key: str | None = Field(default=None, description="key"),
        filter: dict[str, Any] | None = Field(default=None, description="filter"),
        pipeline: list[dict[str, Any]] | None = Field(
            default=None, description="pipeline"
        ),
        client=Depends(get_client),
    ) -> dict:
        # CONCEPT:ECO-4.1
        """Manage analysis operations.

        Actions:
          - 'distinct': Call distinct
          - 'aggregate': Call aggregate
        """
        kwargs: dict[str, Any]
        if action == "distinct":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "key": key,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.distinct(**kwargs)
        if action == "aggregate":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "pipeline": pipeline,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.aggregate(**kwargs)
        raise ValueError(
            f"Unknown action: {action}. Must be one of: distinct', 'aggregate"
        )
