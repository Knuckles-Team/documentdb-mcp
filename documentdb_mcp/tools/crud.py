from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_crud_tools(mcp: FastMCP):
    """Register crud tools.

    CONCEPT:ECO-4.1
    """

    @mcp.tool(tags={"crud"})
    async def documentdb_crud(
        action: str = Field(
            description="Action to perform. Must be one of: 'insert_one', 'insert_many', 'find_one', 'find', 'replace_one', 'update_one', 'update_many', 'delete_one', 'delete_many', 'count_documents', 'find_one_and_update', 'find_one_and_replace', 'find_one_and_delete'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        collection_name: str | None = Field(
            default=None, description="collection name"
        ),
        document: dict[str, Any] | None = Field(default=None, description="document"),
        documents: list[dict[str, Any]] | None = Field(
            default=None, description="documents"
        ),
        filter: dict[str, Any] | None = Field(default=None, description="filter"),
        limit: int | None = Field(default=None, description="limit"),
        skip: int | None = Field(default=None, description="skip"),
        sort: list[Any] | None = Field(default=None, description="sort"),
        replacement: dict[str, Any] | None = Field(
            default=None, description="replacement"
        ),
        update: dict[str, Any] | None = Field(default=None, description="update"),
        return_document: str | None = Field(
            default=None, description="return document"
        ),
        client=Depends(get_client),
    ) -> dict:
        # CONCEPT:ECO-4.1
        """Manage crud operations.

        Actions:
          - 'insert_one': Call insert_one
          - 'insert_many': Call insert_many
          - 'find_one': Call find_one
          - 'find': Call find
          - 'replace_one': Call replace_one
          - 'update_one': Call update_one
          - 'update_many': Call update_many
          - 'delete_one': Call delete_one
          - 'delete_many': Call delete_many
          - 'count_documents': Call count_documents
          - 'find_one_and_update': Call find_one_and_update
          - 'find_one_and_replace': Call find_one_and_replace
          - 'find_one_and_delete': Call find_one_and_delete
        """
        kwargs: dict[str, Any]
        if action == "insert_one":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "document": document,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.insert_one(**kwargs)
        if action == "insert_many":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "documents": documents,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.insert_many(**kwargs)
        if action == "find_one":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.find_one(**kwargs)
        if action == "find":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "limit": limit,
                "skip": skip,
                "sort": sort,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.find(**kwargs)
        if action == "replace_one":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "replacement": replacement,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.replace_one(**kwargs)
        if action == "update_one":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "update": update,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.update_one(**kwargs)
        if action == "update_many":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "update": update,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.update_many(**kwargs)
        if action == "delete_one":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.delete_one(**kwargs)
        if action == "delete_many":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.delete_many(**kwargs)
        if action == "count_documents":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.count_documents(**kwargs)
        if action == "find_one_and_update":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "update": update,
                "return_document": return_document,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.find_one_and_update(**kwargs)
        if action == "find_one_and_replace":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
                "replacement": replacement,
                "return_document": return_document,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.find_one_and_replace(**kwargs)
        if action == "find_one_and_delete":
            kwargs = {
                "database_name": database_name,
                "collection_name": collection_name,
                "filter": filter,
            }
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return client.find_one_and_delete(**kwargs)
        raise ValueError(
            f"Unknown action: {action}. Must be one of: insert_one', 'insert_many', 'find_one', 'find', 'replace_one', 'update_one', 'update_many', 'delete_one', 'delete_many', 'count_documents', 'find_one_and_update', 'find_one_and_replace', 'find_one_and_delete"
        )
