#!/usr/bin/python
import warnings

# Filter RequestsDependencyWarning early to prevent log spam
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from requests.exceptions import RequestsDependencyWarning

        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
    except ImportError:
        pass

# General urllib3/chardet mismatch warnings
warnings.filterwarnings("ignore", message=".*urllib3.*or chardet.*")
warnings.filterwarnings("ignore", message=".*urllib3.*or charset_normalizer.*")

import json
import logging
import os
import sys
from typing import Any

import pymongo
from agent_utilities.base_utilities import to_boolean
from agent_utilities.mcp_utilities import (
    create_mcp_server,
    ctx_confirm_destructive,
    ctx_log,
    ctx_progress,
)
from dotenv import find_dotenv, load_dotenv
from fastmcp import Context, FastMCP
from fastmcp.utilities.logging import get_logger
from pydantic import Field
from pymongo.errors import PyMongoError

__version__ = "0.1.56"

logger = get_logger(name="TokenMiddleware")
logger.setLevel(logging.DEBUG)


_client: pymongo.MongoClient | None = None


def get_client() -> pymongo.MongoClient:
    """Get or initialize the MongoDB client."""
    global _client
    if _client is None:
        uri = os.environ.get("MONGODB_URI")
        if not uri:
            host = os.environ.get("MONGODB_HOST", "localhost")
            port = os.environ.get("MONGODB_PORT", "10260")
            uri = f"mongodb://{host}:{port}/"

        logger.info(f"Connecting to DocumentDB/MongoDB at {uri}")
        try:
            _client = pymongo.MongoClient(uri)
            _client.admin.command("ping")
            logger.info("Successfully connected to DocumentDB/MongoDB")
        except Exception as e:
            logger.error(f"Failed to connect to DocumentDB/MongoDB: {e}")
            raise
    return _client


def parse_json_arg(arg: Any) -> Any:
    """Helper to parse JSON string arguments if they are passed as strings."""
    if isinstance(arg, str):
        try:
            return json.loads(arg)
        except json.JSONDecodeError:
            return arg
    return arg


def serialize_oid(data: Any) -> Any:
    """Recursively convert ObjectId to string for JSON serialization."""
    if isinstance(data, list):
        return [serialize_oid(item) for item in data]
    elif isinstance(data, dict):
        return {k: serialize_oid(v) for k, v in data.items()}
    elif hasattr(data, "__class__") and data.__class__.__name__ == "ObjectId":
        return str(data)
    else:
        return data


def register_misc_tools(mcp: FastMCP):
    pass
    pass


def register_system_tools(mcp: FastMCP):
    @mcp.tool(tags={"system"})
    def binary_version(
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Get the binary version of the server (using buildInfo)."""
        try:
            client = get_client()
            info = client.admin.command("buildInfo")
            return info.get("version", "unknown")
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.tool(tags={"system"})
    def list_databases(
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[str]:
        """List all databases in the connected DocumentDB/MongoDB instance."""
        client = get_client()
        return client.list_database_names()

    @mcp.tool(tags={"system"})
    def run_command(
        database_name: str,
        command: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any]:
        """Run a raw command against the database."""
        client = get_client()
        db = client[database_name]
        cmd = parse_json_arg(command)
        result = db.command(cmd)
        return serialize_oid(result)


def register_collections_tools(mcp: FastMCP):
    @mcp.tool(tags={"collections"})
    def list_collections(
        database_name: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[str]:
        """List all collections in a specific database."""
        client = get_client()
        db = client[database_name]
        return db.list_collection_names()

    @mcp.tool(tags={"collections"})
    def create_collection(
        database_name: str,
        collection_name: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Create a new collection in the specified database."""
        client = get_client()
        db = client[database_name]
        try:
            db.create_collection(collection_name)
            return (
                f"Collection '{collection_name}' created in database '{database_name}'"
            )
        except PyMongoError as e:
            return f"Error creating collection: {str(e)}"

    @mcp.tool(tags={"collections"})
    async def drop_collection(
        database_name: str,
        collection_name: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str | dict[str, Any]:
        """Drop a collection from the specified database."""
        if not await ctx_confirm_destructive(ctx, "drop collection"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        db = client[database_name]
        try:
            db.drop_collection(collection_name)
            return f"Collection '{collection_name}' dropped from database '{database_name}'"
        except PyMongoError as e:
            return f"Error dropping collection: {str(e)}"

    @mcp.tool(tags={"collections"})
    def create_database(
        database_name: str,
        initial_collection: str = "default_collection",
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Explicitly create a database by creating a collection in it (MongoDB creates DBs lazily)."""
        client = get_client()
        db = client[database_name]
        try:
            db.create_collection(initial_collection)
            return f"Collection '{initial_collection}' created in database '{database_name}'"
        except PyMongoError as e:
            return f"Error creating collection: {str(e)}"

    @mcp.tool(tags={"collections"})
    async def drop_database(
        database_name: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str | dict[str, Any]:
        """Drop a database."""
        if not await ctx_confirm_destructive(ctx, "drop database"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        try:
            client.drop_database(database_name)
            return f"Database '{database_name}' dropped"
        except PyMongoError as e:
            return f"Error dropping database: {str(e)}"

    @mcp.tool(tags={"collections"})
    def rename_collection(
        database_name: str,
        old_name: str,
        new_name: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Rename a collection."""
        client = get_client()
        db = client[database_name]
        try:
            db[old_name].rename(new_name)
            return f"Collection '{old_name}' renamed to '{new_name}'"
        except PyMongoError as e:
            return f"Error renaming collection: {str(e)}"


def register_users_tools(mcp: FastMCP):
    @mcp.tool(tags={"users"})
    def create_user(
        database_name: str,
        username: str,
        password: str,
        roles: list[Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Create a new user on the specified database."""
        client = get_client()
        db = client[database_name]
        try:
            parsed_roles = parse_json_arg(roles)
            db.command("createUser", username, pwd=password, roles=parsed_roles)
            return f"User '{username}' created on '{database_name}'"
        except PyMongoError as e:
            return f"Error creating user: {str(e)}"

    @mcp.tool(tags={"users"})
    async def drop_user(
        database_name: str,
        username: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str | dict[str, Any]:
        """Drop a user from the specified database."""
        if not await ctx_confirm_destructive(ctx, "drop user"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        db = client[database_name]
        try:
            db.command("dropUser", username)
            return f"User '{username}' dropped from '{database_name}'"
        except PyMongoError as e:
            return f"Error dropping user: {str(e)}"

    @mcp.tool(tags={"users"})
    def update_user(
        database_name: str,
        username: str,
        password: str | None = None,
        roles: list[Any] | None = None,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Update a user's password or roles."""
        client = get_client()
        db = client[database_name]
        update_fields = {}
        if password:
            update_fields["pwd"] = password
        if roles:
            update_fields["roles"] = parse_json_arg(roles)

        if not update_fields:
            return "No updates specified."

        try:
            db.command("updateUser", username, **update_fields)
            return f"User '{username}' updated on '{database_name}'"
        except PyMongoError as e:
            return f"Error updating user: {str(e)}"

    @mcp.tool(tags={"users"})
    def users_info(
        database_name: str,
        username: str,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any]:
        """Get information about a user."""
        client = get_client()
        db = client[database_name]
        try:
            result = db.command("usersInfo", username)
            return serialize_oid(result)
        except PyMongoError as e:
            return {"error": str(e)}


def register_crud_tools(mcp: FastMCP):
    @mcp.tool(tags={"crud"})
    def insert_one(
        database_name: str,
        collection_name: str,
        document: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Insert a single document into a collection."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        doc = parse_json_arg(document)
        try:
            result = col.insert_one(doc)
            return str(result.inserted_id)
        except PyMongoError as e:
            return f"Error inserting document: {str(e)}"

    @mcp.tool(tags={"crud"})
    def insert_many(
        database_name: str,
        collection_name: str,
        documents: list[dict[str, Any]],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[str]:
        """Insert multiple documents into a collection."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        docs = [parse_json_arg(d) for d in documents]
        try:
            result = col.insert_many(docs)
            return [str(id) for id in result.inserted_ids]
        except PyMongoError as e:
            return [f"Error inserting documents: {str(e)}"]

    @mcp.tool(tags={"crud"})
    def find_one(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any] | None:
        """Find a single document matching the filter."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.find_one(query)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}

    @mcp.tool(tags={"crud"})
    def find(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        limit: int = 20,
        skip: int = 0,
        sort: list[Any] | None = None,
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[dict[str, Any]]:
        """
        Find documents matching the filter.
        'sort' should be a list of [key, direction] pairs, e.g. [["name", 1], ["date", -1]].
        """
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            cursor = col.find(query)
            if sort:
                s = parse_json_arg(sort)
                cursor = cursor.sort(s)

            if skip > 0:
                cursor = cursor.skip(skip)

            if limit > 0:
                cursor = cursor.limit(limit)

            results = []
            for doc in cursor:
                results.append(serialize_oid(doc))
            return results
        except PyMongoError as e:
            return [{"error": str(e)}]

    @mcp.tool(tags={"crud"})
    def replace_one(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        replacement: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Replace a single document matching the filter."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        repl = parse_json_arg(replacement)
        try:
            result = col.replace_one(query, repl)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error replacing document: {str(e)}"

    @mcp.tool(tags={"crud"})
    def update_one(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Update a single document matching the filter. 'update' must contain update operators like $set."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        upd = parse_json_arg(update)
        try:
            result = col.update_one(query, upd)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error updating document: {str(e)}"

    @mcp.tool(tags={"crud"})
    def update_many(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str:
        """Update multiple documents matching the filter."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        upd = parse_json_arg(update)
        try:
            result = col.update_many(query, upd)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error updating documents: {str(e)}"

    @mcp.tool(tags={"crud"})
    async def delete_one(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str | dict[str, Any]:
        """Delete a single document matching the filter."""
        if not await ctx_confirm_destructive(ctx, "delete one"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.delete_one(query)
            return f"Deleted: {result.deleted_count}"
        except PyMongoError as e:
            return f"Error deleting document: {str(e)}"

    @mcp.tool(tags={"crud"})
    async def delete_many(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> str | dict[str, Any]:
        """Delete multiple documents matching the filter."""
        if not await ctx_confirm_destructive(ctx, "delete many"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.delete_many(query)
            return f"Deleted: {result.deleted_count}"
        except PyMongoError as e:
            return f"Error deleting documents: {str(e)}"

    @mcp.tool(tags={"crud"})
    def count_documents(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> int:
        """Count documents matching the filter."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            return col.count_documents(query)
        except PyMongoError as e:
            ctx_log(ctx, logger, "error", f"Error counting documents: {e}")
            return -1

    @mcp.tool(tags={"crud"})
    def find_one_and_update(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
        return_document: str = "before",
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any] | None:
        """Finds a single document and updates it. return_document: 'before' or 'after'."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        upd = parse_json_arg(update)
        ret_doc = (
            pymongo.ReturnDocument.AFTER
            if return_document.lower() == "after"
            else pymongo.ReturnDocument.BEFORE
        )
        try:
            result = col.find_one_and_update(query, upd, return_document=ret_doc)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}

    @mcp.tool(tags={"crud"})
    def find_one_and_replace(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        replacement: dict[str, Any],
        return_document: str = "before",
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any] | None:
        """Finds a single document and replaces it. return_document: 'before' or 'after'."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        repl = parse_json_arg(replacement)
        ret_doc = (
            pymongo.ReturnDocument.AFTER
            if return_document.lower() == "after"
            else pymongo.ReturnDocument.BEFORE
        )
        try:
            result = col.find_one_and_replace(query, repl, return_document=ret_doc)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}

    @mcp.tool(tags={"crud"})
    async def find_one_and_delete(
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict[str, Any] | None:
        """Finds a single document and deletes it."""
        if not await ctx_confirm_destructive(ctx, "find one and delete"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.find_one_and_delete(query)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}


def register_analysis_tools(mcp: FastMCP):
    @mcp.tool(tags={"analysis"})
    def distinct(
        database_name: str,
        collection_name: str,
        key: str,
        filter: dict[str, Any],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[Any]:
        """Find distinct values for a key."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            return col.distinct(key, query)
        except PyMongoError as e:
            return [f"Error getting distinct values: {str(e)}"]

    @mcp.tool(tags={"analysis"})
    def aggregate(
        database_name: str,
        collection_name: str,
        pipeline: list[dict[str, Any]],
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> list[dict[str, Any]]:
        """Run an aggregation pipeline."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        pipe = parse_json_arg(pipeline)
        try:
            cursor = col.aggregate(pipe)
            results = []
            for doc in cursor:
                results.append(serialize_oid(doc))
            return results
        except PyMongoError as e:
            return [{"error": str(e)}]


def register_prompts(mcp: FastMCP):
    print(f"documentdb_mcp v{__version__}")

    @mcp.prompt
    def create_user_prompt(user: str) -> str:
        """
        Generates a prompt for creating a user.
        """
        return f"Create a new user: {user}"


def get_mcp_instance() -> tuple[Any, Any, Any, Any]:
    """Initialize and return the MCP instance, args, and middlewares."""
    load_dotenv(find_dotenv())

    args, mcp, middlewares = create_mcp_server(
        name="DocumentDB",
        version=__version__,
        instructions="DocumentDB/MongoDB MCP Server - Manage databases, collections, users, and perform CRUD operations.",
    )

    DEFAULT_MISCTOOL = to_boolean(os.getenv("MISCTOOL", "True"))
    if DEFAULT_MISCTOOL:
        register_misc_tools(mcp)
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
    register_prompts(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)
    registered_tags: list[str] = []
    return mcp, args, middlewares, registered_tags


def mcp_server() -> None:
    mcp, args, middlewares, registered_tags = get_mcp_instance()
    print(f"{'documentdb-mcp'} MCP v{__version__}", file=sys.stderr)
    print("\nStarting MCP Server", file=sys.stderr)
    print(f"  Transport: {args.transport.upper()}", file=sys.stderr)
    print(f"  Auth: {args.auth_type}", file=sys.stderr)
    print(f"  Dynamic Tags Loaded: {len(set(registered_tags))}", file=sys.stderr)

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
