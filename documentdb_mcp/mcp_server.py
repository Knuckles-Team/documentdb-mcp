#!/usr/bin/python
import warnings

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from fastmcp.utilities.logging import get_logger
from pydantic import Field

# Filter RequestsDependencyWarning early to prevent log spam
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from requests.exceptions import RequestsDependencyWarning

        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
    except ImportError:
        pass

warnings.filterwarnings("ignore", message=".*urllib3.*or chardet.*")
warnings.filterwarnings("ignore", message=".*urllib3.*or charset_normalizer.*")

import logging
import os
import sys
from typing import Any

from agent_utilities.base_utilities import to_boolean
from agent_utilities.mcp_utilities import create_mcp_server
from dotenv import find_dotenv, load_dotenv
from starlette.requests import Request
from starlette.responses import JSONResponse

from documentdb_mcp.auth import get_client

__version__ = "0.10.1"

logger = get_logger(name="documentdb-mcp")
logger.setLevel(logging.INFO)


def register_system_tools(mcp: FastMCP):
    @mcp.tool(tags={"system"})
    async def documentdb_system(
        action: str = Field(
            description="Action to perform. Must be one of: 'binary_version', 'list_databases', 'run_command'"
        ),
        database_name: str | None = Field(default=None, description="database name"),
        command: dict[str, Any] | None = Field(default=None, description="command"),
        client=Depends(get_client),
    ) -> dict:
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


def register_collections_tools(mcp: FastMCP):
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


def register_users_tools(mcp: FastMCP):
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


def register_crud_tools(mcp: FastMCP):
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


def register_analysis_tools(mcp: FastMCP):
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


def get_mcp_instance() -> tuple[Any, ...]:
    """Initialize and return the MCP instance."""
    load_dotenv(find_dotenv())
    args, mcp, middlewares = create_mcp_server(
        name="documentdb-mcp MCP",
        version=__version__,
        instructions="documentdb-mcp MCP Server — Condensed Action-Routed Tools.",
    )

    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "OK"})

    DEFAULT_SYSTEMTOOL = to_boolean(os.getenv("SYSTEMTOOL", "True"))
    if DEFAULT_SYSTEMTOOL:
        register_system_tools(mcp)
    DEFAULT_COLLECTIONSTOOL = to_boolean(os.getenv("COLLECTIONSTOOL", "True"))
    if DEFAULT_COLLECTIONSTOOL:
        register_collections_tools(mcp)
    DEFAULT_USERSTOOL = to_boolean(os.getenv("USERSTOOL", "True"))
    if DEFAULT_USERSTOOL:
        register_users_tools(mcp)
    DEFAULT_CRUDTOOL = to_boolean(os.getenv("CRUDTOOL", "True"))
    if DEFAULT_CRUDTOOL:
        register_crud_tools(mcp)
    DEFAULT_ANALYSISTOOL = to_boolean(os.getenv("ANALYSISTOOL", "True"))
    if DEFAULT_ANALYSISTOOL:
        register_analysis_tools(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)
    return mcp, args, middlewares


def mcp_server() -> None:
    mcp, args, middlewares = get_mcp_instance()
    print(f"documentdb-mcp MCP v{__version__}", file=sys.stderr)
    print("\nStarting MCP Server", file=sys.stderr)
    print(f"  Transport: {args.transport.upper()}", file=sys.stderr)
    print(f"  Auth: {args.auth_type}", file=sys.stderr)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.error("Invalid transport", extra={"transport": args.transport})
        sys.exit(1)


if __name__ == "__main__":
    mcp_server()
