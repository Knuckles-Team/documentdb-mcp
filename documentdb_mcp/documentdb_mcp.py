#!/usr/bin/python
# coding: utf-8

import os
import argparse
import sys
import logging
from typing import Optional, List, Dict, Union, Any


import json
import pymongo
from pymongo.errors import PyMongoError
import requests
from eunomia_mcp.middleware import EunomiaMcpMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastmcp import FastMCP
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth import OAuthProxy, RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.server.middleware.timing import TimingMiddleware
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware
from fastmcp.utilities.logging import get_logger
from documentdb_mcp.utils import to_boolean, to_integer
from documentdb_mcp.middlewares import UserTokenMiddleware, JWTClaimsLoggingMiddleware

__version__ = "0.0.16"

logger = get_logger(name="TokenMiddleware")
logger.setLevel(logging.DEBUG)

config = {
    "enable_delegation": to_boolean(os.environ.get("ENABLE_DELEGATION", "False")),
    "audience": os.environ.get("AUDIENCE", None),
    "delegated_scopes": os.environ.get("DELEGATED_SCOPES", "api"),
    "token_endpoint": None,  # Will be fetched dynamically from OIDC config
    "oidc_client_id": os.environ.get("OIDC_CLIENT_ID", None),
    "oidc_client_secret": os.environ.get("OIDC_CLIENT_SECRET", None),
    "oidc_config_url": os.environ.get("OIDC_CONFIG_URL", None),
    "jwt_jwks_uri": os.getenv("FASTMCP_SERVER_AUTH_JWT_JWKS_URI", None),
    "jwt_issuer": os.getenv("FASTMCP_SERVER_AUTH_JWT_ISSUER", None),
    "jwt_audience": os.getenv("FASTMCP_SERVER_AUTH_JWT_AUDIENCE", None),
    "jwt_algorithm": os.getenv("FASTMCP_SERVER_AUTH_JWT_ALGORITHM", None),
    "jwt_secret": os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY", None),
    "jwt_required_scopes": os.getenv("FASTMCP_SERVER_AUTH_JWT_REQUIRED_SCOPES", None),
}

DEFAULT_TRANSPORT = os.getenv("TRANSPORT", "stdio")
DEFAULT_HOST = os.getenv("HOST", "0.0.0.0")
DEFAULT_PORT = to_integer(string=os.getenv("PORT", "8000"))

# Global client variable (lazy initialization)
_client: Optional[pymongo.MongoClient] = None


def get_client() -> pymongo.MongoClient:
    """Get or initialize the MongoDB client."""
    global _client
    if _client is None:
        uri = os.environ.get("MONGODB_URI")
        if not uri:
            # Check for MONGODB_HOST, MONGODB_PORT etc as fallback or default
            host = os.environ.get("MONGODB_HOST", "localhost")
            port = os.environ.get("MONGODB_PORT", "10260")
            uri = f"mongodb://{host}:{port}/"

        logger.info(f"Connecting to DocumentDB/MongoDB at {uri}")
        try:
            _client = pymongo.MongoClient(uri)
            # Connectivity check
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
            # If it's not valid JSON, assume it's a simple string or the user intended it as is
            # For complex filter queries passed as string, this allows "{\"x\": 1}" to become {"x": 1}
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


def register_tools(mcp: FastMCP):
    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "OK"})

    @mcp.tool(tags={"system"})
    def binary_version() -> str:
        """Get the binary version of the server (using buildInfo)."""
        try:
            client = get_client()
            info = client.admin.command("buildInfo")
            return info.get("version", "unknown")
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.tool(tags={"system"})
    def list_databases() -> List[str]:
        """List all databases in the connected DocumentDB/MongoDB instance."""
        client = get_client()
        return client.list_database_names()

    @mcp.tool(tags={"system"})
    def run_command(database_name: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Run a raw command against the database."""
        client = get_client()
        db = client[database_name]
        cmd = parse_json_arg(command)
        result = db.command(cmd)
        return serialize_oid(result)

    @mcp.tool(tags={"collections"})
    def list_collections(database_name: str) -> List[str]:
        """List all collections in a specific database."""
        client = get_client()
        db = client[database_name]
        return db.list_collection_names()

    @mcp.tool(tags={"collections"})
    def create_collection(database_name: str, collection_name: str) -> str:
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
    def drop_collection(database_name: str, collection_name: str) -> str:
        """Drop a collection from the specified database."""
        client = get_client()
        db = client[database_name]
        try:
            db.drop_collection(collection_name)
            return f"Collection '{collection_name}' dropped from database '{database_name}'"
        except PyMongoError as e:
            return f"Error dropping collection: {str(e)}"

    @mcp.tool(tags={"collections"})
    def create_database(
        database_name: str, initial_collection: str = "default_collection"
    ) -> str:
        """Explicitly create a database by creating a collection in it (MongoDB creates DBs lazily)."""
        # This maps loosely to create_database, but typically we just start using it.
        client = get_client()
        db = client[database_name]
        try:
            db.create_collection(initial_collection)
            return f"Collection '{initial_collection}' created in database '{database_name}'"
        except PyMongoError as e:
            return f"Error creating collection: {str(e)}"

    @mcp.tool(tags={"collections"})
    def drop_database(database_name: str) -> str:
        """Drop a database."""
        client = get_client()
        try:
            client.drop_database(database_name)
            return f"Database '{database_name}' dropped"
        except PyMongoError as e:
            return f"Error dropping database: {str(e)}"

    @mcp.tool(tags={"collections"})
    def rename_collection(database_name: str, old_name: str, new_name: str) -> str:
        """Rename a collection."""
        client = get_client()
        db = client[database_name]
        try:
            db[old_name].rename(new_name)
            return f"Collection '{old_name}' renamed to '{new_name}'"
        except PyMongoError as e:
            return f"Error renaming collection: {str(e)}"

    @mcp.tool(tags={"users"})
    def create_user(
        database_name: str, username: str, password: str, roles: List[Any]
    ) -> str:
        """Create a new user on the specified database."""
        client = get_client()
        db = client[database_name]
        try:
            # roles can be list of strings or list of dicts (e.g. [{'role': 'read', 'db': 'test'}])
            parsed_roles = parse_json_arg(roles)
            db.command("createUser", username, pwd=password, roles=parsed_roles)
            return f"User '{username}' created on '{database_name}'"
        except PyMongoError as e:
            return f"Error creating user: {str(e)}"

    @mcp.tool(tags={"users"})
    def drop_user(database_name: str, username: str) -> str:
        """Drop a user from the specified database."""
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
        password: Optional[str] = None,
        roles: Optional[List[Any]] = None,
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
    def users_info(database_name: str, username: str) -> Dict[str, Any]:
        """Get information about a user."""
        client = get_client()
        db = client[database_name]
        try:
            result = db.command("usersInfo", username)
            return serialize_oid(result)
        except PyMongoError as e:
            return {"error": str(e)}

    @mcp.tool(tags={"crud"})
    def insert_one(
        database_name: str, collection_name: str, document: Dict[str, Any]
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
        database_name: str, collection_name: str, documents: List[Dict[str, Any]]
    ) -> List[str]:
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
        database_name: str, collection_name: str, filter: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
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
        filter: Dict[str, Any],
        limit: int = 20,
        skip: int = 0,
        sort: Optional[List[Any]] = None,
    ) -> List[Dict[str, Any]]:
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
                # Parse sort if it comes as string
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
        filter: Dict[str, Any],
        replacement: Dict[str, Any],
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
        filter: Dict[str, Any],
        update: Dict[str, Any],
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
        filter: Dict[str, Any],
        update: Dict[str, Any],
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
    def delete_one(
        database_name: str, collection_name: str, filter: Dict[str, Any]
    ) -> str:
        """Delete a single document matching the filter."""
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
    def delete_many(
        database_name: str, collection_name: str, filter: Dict[str, Any]
    ) -> str:
        """Delete multiple documents matching the filter."""
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
        database_name: str, collection_name: str, filter: Dict[str, Any]
    ) -> int:
        """Count documents matching the filter."""
        client = get_client()
        db = client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            return col.count_documents(query)
        except PyMongoError as e:
            logger.error(f"Error counting documents: {e}")
            return -1

    @mcp.tool(tags={"analysis"})
    def distinct(
        database_name: str, collection_name: str, key: str, filter: Dict[str, Any]
    ) -> List[Any]:
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
        database_name: str, collection_name: str, pipeline: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
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

    @mcp.tool(tags={"crud"})
    def find_one_and_update(
        database_name: str,
        collection_name: str,
        filter: Dict[str, Any],
        update: Dict[str, Any],
        return_document: str = "before",
    ) -> Optional[Dict[str, Any]]:
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
        filter: Dict[str, Any],
        replacement: Dict[str, Any],
        return_document: str = "before",
    ) -> Optional[Dict[str, Any]]:
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
    def find_one_and_delete(
        database_name: str, collection_name: str, filter: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Finds a single document and deletes it."""
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


def register_prompts(mcp: FastMCP):
    print(f"documentdb_mcp v{__version__}")

    @mcp.prompt
    def create_user_prompt(user: str) -> str:
        """
        Generates a prompt for creating a user.
        """
        return f"Create a new user: {user}"


def documentdb_mcp():
    parser = argparse.ArgumentParser(description="DocumentDB MCP Server")
    parser.add_argument(
        "-t",
        "--transport",
        default=DEFAULT_TRANSPORT,
        choices=["stdio", "streamable-http", "sse"],
        help="Transport method: 'stdio', 'streamable-http', or 'sse' [legacy] (default: stdio)",
    )
    parser.add_argument(
        "-s",
        "--host",
        default=DEFAULT_HOST,
        help="Host address for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Port number for HTTP transport (default: 8000)",
    )
    parser.add_argument(
        "--auth-type",
        default="none",
        choices=["none", "static", "jwt", "oauth-proxy", "oidc-proxy", "remote-oauth"],
        help="Authentication type for MCP server: 'none' (disabled), 'static' (internal), 'jwt' (external token verification), 'oauth-proxy', 'oidc-proxy', 'remote-oauth' (external) (default: none)",
    )
    # JWT/Token params
    parser.add_argument(
        "--token-jwks-uri", default=None, help="JWKS URI for JWT verification"
    )
    parser.add_argument(
        "--token-issuer", default=None, help="Issuer for JWT verification"
    )
    parser.add_argument(
        "--token-audience", default=None, help="Audience for JWT verification"
    )
    parser.add_argument(
        "--token-algorithm",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_ALGORITHM"),
        choices=[
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
        ],
        help="JWT signing algorithm (required for HMAC or static key). Auto-detected for JWKS.",
    )
    parser.add_argument(
        "--token-secret",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY"),
        help="Shared secret for HMAC (HS*) or PEM public key for static asymmetric verification.",
    )
    parser.add_argument(
        "--token-public-key",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY"),
        help="Path to PEM public key file or inline PEM string (for static asymmetric keys).",
    )
    parser.add_argument(
        "--required-scopes",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_REQUIRED_SCOPES"),
        help="Comma-separated list of required scopes (e.g., documentdb.read,documentdb.write).",
    )
    # OAuth Proxy params
    parser.add_argument(
        "--oauth-upstream-auth-endpoint",
        default=None,
        help="Upstream authorization endpoint for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-token-endpoint",
        default=None,
        help="Upstream token endpoint for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-client-id",
        default=None,
        help="Upstream client ID for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-client-secret",
        default=None,
        help="Upstream client secret for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-base-url", default=None, help="Base URL for OAuth Proxy"
    )
    # OIDC Proxy params
    parser.add_argument(
        "--oidc-config-url", default=None, help="OIDC configuration URL"
    )
    parser.add_argument("--oidc-client-id", default=None, help="OIDC client ID")
    parser.add_argument("--oidc-client-secret", default=None, help="OIDC client secret")
    parser.add_argument("--oidc-base-url", default=None, help="Base URL for OIDC Proxy")
    # Remote OAuth params
    parser.add_argument(
        "--remote-auth-servers",
        default=None,
        help="Comma-separated list of authorization servers for Remote OAuth",
    )
    parser.add_argument(
        "--remote-base-url", default=None, help="Base URL for Remote OAuth"
    )
    # Common
    parser.add_argument(
        "--allowed-client-redirect-uris",
        default=None,
        help="Comma-separated list of allowed client redirect URIs",
    )
    # Eunomia params
    parser.add_argument(
        "--eunomia-type",
        default="none",
        choices=["none", "embedded", "remote"],
        help="Eunomia authorization type: 'none' (disabled), 'embedded' (built-in), 'remote' (external) (default: none)",
    )
    parser.add_argument(
        "--eunomia-policy-file",
        default="mcp_policies.json",
        help="Policy file for embedded Eunomia (default: mcp_policies.json)",
    )
    parser.add_argument(
        "--eunomia-remote-url", default=None, help="URL for remote Eunomia server"
    )
    # Delegation params
    parser.add_argument(
        "--enable-delegation",
        action="store_true",
        default=to_boolean(os.environ.get("ENABLE_DELEGATION", "False")),
        help="Enable OIDC token delegation",
    )
    parser.add_argument(
        "--audience",
        default=os.environ.get("AUDIENCE", None),
        help="Audience for the delegated token",
    )
    parser.add_argument(
        "--delegated-scopes",
        default=os.environ.get("DELEGATED_SCOPES", "api"),
        help="Scopes for the delegated token (space-separated)",
    )
    parser.add_argument(
        "--openapi-file",
        default=None,
        help="Path to the OpenAPI JSON file to import additional tools from",
    )
    parser.add_argument(
        "--openapi-base-url",
        default=None,
        help="Base URL for the OpenAPI client (overrides instance URL)",
    )
    parser.add_argument(
        "--openapi-use-token",
        action="store_true",
        help="Use the incoming Bearer token (from MCP request) to authenticate OpenAPI import",
    )

    parser.add_argument(
        "--openapi-username",
        default=os.getenv("OPENAPI_USERNAME"),
        help="Username for basic auth during OpenAPI import",
    )

    parser.add_argument(
        "--openapi-password",
        default=os.getenv("OPENAPI_PASSWORD"),
        help="Password for basic auth during OpenAPI import",
    )

    parser.add_argument(
        "--openapi-client-id",
        default=os.getenv("OPENAPI_CLIENT_ID"),
        help="OAuth client ID for OpenAPI import",
    )

    parser.add_argument(
        "--openapi-client-secret",
        default=os.getenv("OPENAPI_CLIENT_SECRET"),
        help="OAuth client secret for OpenAPI import",
    )

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

    # Update config with CLI arguments
    config["enable_delegation"] = args.enable_delegation
    config["audience"] = args.audience or config["audience"]
    config["delegated_scopes"] = args.delegated_scopes or config["delegated_scopes"]
    config["oidc_config_url"] = args.oidc_config_url or config["oidc_config_url"]
    config["oidc_client_id"] = args.oidc_client_id or config["oidc_client_id"]
    config["oidc_client_secret"] = (
        args.oidc_client_secret or config["oidc_client_secret"]
    )

    # Configure delegation if enabled
    if config["enable_delegation"]:
        if args.auth_type != "oidc-proxy":
            logger.error("Token delegation requires auth-type=oidc-proxy")
            sys.exit(1)
        if not config["audience"]:
            logger.error("audience is required for delegation")
            sys.exit(1)
        if not all(
            [
                config["oidc_config_url"],
                config["oidc_client_id"],
                config["oidc_client_secret"],
            ]
        ):
            logger.error(
                "Delegation requires complete OIDC configuration (oidc-config-url, oidc-client-id, oidc-client-secret)"
            )
            sys.exit(1)

        # Fetch OIDC configuration to get token_endpoint
        try:
            logger.info(
                "Fetching OIDC configuration",
                extra={"oidc_config_url": config["oidc_config_url"]},
            )
            oidc_config_resp = requests.get(config["oidc_config_url"])
            oidc_config_resp.raise_for_status()
            oidc_config = oidc_config_resp.json()
            config["token_endpoint"] = oidc_config.get("token_endpoint")
            if not config["token_endpoint"]:
                logger.error("No token_endpoint found in OIDC configuration")
                raise ValueError("No token_endpoint found in OIDC configuration")
            logger.info(
                "OIDC configuration fetched successfully",
                extra={"token_endpoint": config["token_endpoint"]},
            )
        except Exception as e:
            print(f"Failed to fetch OIDC configuration: {e}")
            logger.error(
                "Failed to fetch OIDC configuration",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            sys.exit(1)

    # Set auth based on type
    auth = None
    allowed_uris = (
        args.allowed_client_redirect_uris.split(",")
        if args.allowed_client_redirect_uris
        else None
    )

    if args.auth_type == "none":
        auth = None
    elif args.auth_type == "static":
        auth = StaticTokenVerifier(
            tokens={
                "test-token": {"client_id": "test-user", "scopes": ["read", "write"]},
                "admin-token": {"client_id": "admin", "scopes": ["admin"]},
            }
        )
    elif args.auth_type == "jwt":
        # Fallback to env vars if not provided via CLI
        jwks_uri = args.token_jwks_uri or os.getenv("FASTMCP_SERVER_AUTH_JWT_JWKS_URI")
        issuer = args.token_issuer or os.getenv("FASTMCP_SERVER_AUTH_JWT_ISSUER")
        audience = args.token_audience or os.getenv("FASTMCP_SERVER_AUTH_JWT_AUDIENCE")
        algorithm = args.token_algorithm
        secret_or_key = args.token_secret or args.token_public_key
        public_key_pem = None

        if not (jwks_uri or secret_or_key):
            logger.error(
                "JWT auth requires either --token-jwks-uri or --token-secret/--token-public-key"
            )
            sys.exit(1)
        if not (issuer and audience):
            logger.error("JWT requires --token-issuer and --token-audience")
            sys.exit(1)

        # Load static public key from file if path is given
        if args.token_public_key and os.path.isfile(args.token_public_key):
            try:
                with open(args.token_public_key, "r") as f:
                    public_key_pem = f.read()
                logger.info(f"Loaded static public key from {args.token_public_key}")
            except Exception as e:
                print(f"Failed to read public key file: {e}")
                logger.error(f"Failed to read public key file: {e}")
                sys.exit(1)
        elif args.token_public_key:
            public_key_pem = args.token_public_key  # Inline PEM

        # Validation: Conflicting options
        if jwks_uri and (algorithm or secret_or_key):
            logger.warning(
                "JWKS mode ignores --token-algorithm and --token-secret/--token-public-key"
            )

        # HMAC mode
        if algorithm and algorithm.startswith("HS"):
            if not secret_or_key:
                logger.error(f"HMAC algorithm {algorithm} requires --token-secret")
                sys.exit(1)
            if jwks_uri:
                logger.error("Cannot use --token-jwks-uri with HMAC")
                sys.exit(1)
            public_key = secret_or_key
        else:
            public_key = public_key_pem

        # Required scopes
        required_scopes = None
        if args.required_scopes:
            required_scopes = [
                s.strip() for s in args.required_scopes.split(",") if s.strip()
            ]

        try:
            auth = JWTVerifier(
                jwks_uri=jwks_uri,
                public_key=public_key,
                issuer=issuer,
                audience=audience,
                algorithm=(
                    algorithm if algorithm and algorithm.startswith("HS") else None
                ),
                required_scopes=required_scopes,
            )
            logger.info(
                "JWTVerifier configured",
                extra={
                    "mode": (
                        "JWKS"
                        if jwks_uri
                        else (
                            "HMAC"
                            if algorithm and algorithm.startswith("HS")
                            else "Static Key"
                        )
                    ),
                    "algorithm": algorithm,
                    "required_scopes": required_scopes,
                },
            )
        except Exception as e:
            print(f"Failed to initialize JWTVerifier: {e}")
            logger.error(f"Failed to initialize JWTVerifier: {e}")
            sys.exit(1)
    elif args.auth_type == "oauth-proxy":
        if not (
            args.oauth_upstream_auth_endpoint
            and args.oauth_upstream_token_endpoint
            and args.oauth_upstream_client_id
            and args.oauth_upstream_client_secret
            and args.oauth_base_url
            and args.token_jwks_uri
            and args.token_issuer
            and args.token_audience
        ):
            print(
                "oauth-proxy requires oauth-upstream-auth-endpoint, oauth-upstream-token-endpoint, "
                "oauth-upstream-client-id, oauth-upstream-client-secret, oauth-base-url, token-jwks-uri, "
                "token-issuer, token-audience"
            )
            logger.error(
                "oauth-proxy requires oauth-upstream-auth-endpoint, oauth-upstream-token-endpoint, "
                "oauth-upstream-client-id, oauth-upstream-client-secret, oauth-base-url, token-jwks-uri, "
                "token-issuer, token-audience",
                extra={
                    "auth_endpoint": args.oauth_upstream_auth_endpoint,
                    "token_endpoint": args.oauth_upstream_token_endpoint,
                    "client_id": args.oauth_upstream_client_id,
                    "base_url": args.oauth_base_url,
                    "jwks_uri": args.token_jwks_uri,
                    "issuer": args.token_issuer,
                    "audience": args.token_audience,
                },
            )
            sys.exit(1)
        token_verifier = JWTVerifier(
            jwks_uri=args.token_jwks_uri,
            issuer=args.token_issuer,
            audience=args.token_audience,
        )
        auth = OAuthProxy(
            upstream_authorization_endpoint=args.oauth_upstream_auth_endpoint,
            upstream_token_endpoint=args.oauth_upstream_token_endpoint,
            upstream_client_id=args.oauth_upstream_client_id,
            upstream_client_secret=args.oauth_upstream_client_secret,
            token_verifier=token_verifier,
            base_url=args.oauth_base_url,
            allowed_client_redirect_uris=allowed_uris,
        )
    elif args.auth_type == "oidc-proxy":
        if not (
            args.oidc_config_url
            and args.oidc_client_id
            and args.oidc_client_secret
            and args.oidc_base_url
        ):
            logger.error(
                "oidc-proxy requires oidc-config-url, oidc-client-id, oidc-client-secret, oidc-base-url",
                extra={
                    "config_url": args.oidc_config_url,
                    "client_id": args.oidc_client_id,
                    "base_url": args.oidc_base_url,
                },
            )
            sys.exit(1)
        auth = OIDCProxy(
            config_url=args.oidc_config_url,
            client_id=args.oidc_client_id,
            client_secret=args.oidc_client_secret,
            base_url=args.oidc_base_url,
            allowed_client_redirect_uris=allowed_uris,
        )
    elif args.auth_type == "remote-oauth":
        if not (
            args.remote_auth_servers
            and args.remote_base_url
            and args.token_jwks_uri
            and args.token_issuer
            and args.token_audience
        ):
            logger.error(
                "remote-oauth requires remote-auth-servers, remote-base-url, token-jwks-uri, token-issuer, token-audience",
                extra={
                    "auth_servers": args.remote_auth_servers,
                    "base_url": args.remote_base_url,
                    "jwks_uri": args.token_jwks_uri,
                    "issuer": args.token_issuer,
                    "audience": args.token_audience,
                },
            )
            sys.exit(1)
        auth_servers = [url.strip() for url in args.remote_auth_servers.split(",")]
        token_verifier = JWTVerifier(
            jwks_uri=args.token_jwks_uri,
            issuer=args.token_issuer,
            audience=args.token_audience,
        )
        auth = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=auth_servers,
            base_url=args.remote_base_url,
        )

    # === 2. Build Middleware List ===
    middlewares: List[
        Union[
            UserTokenMiddleware,
            ErrorHandlingMiddleware,
            RateLimitingMiddleware,
            TimingMiddleware,
            LoggingMiddleware,
            JWTClaimsLoggingMiddleware,
            EunomiaMcpMiddleware,
        ]
    ] = [
        ErrorHandlingMiddleware(include_traceback=True, transform_errors=True),
        RateLimitingMiddleware(max_requests_per_second=10.0, burst_capacity=20),
        TimingMiddleware(),
        LoggingMiddleware(),
        JWTClaimsLoggingMiddleware(),
    ]
    if config["enable_delegation"] or args.auth_type == "jwt":
        middlewares.insert(0, UserTokenMiddleware(config=config))  # Must be first

    if args.eunomia_type in ["embedded", "remote"]:
        try:
            from eunomia_mcp import create_eunomia_middleware

            policy_file = args.eunomia_policy_file or "mcp_policies.json"
            eunomia_endpoint = (
                args.eunomia_remote_url if args.eunomia_type == "remote" else None
            )
            eunomia_mw = create_eunomia_middleware(
                policy_file=policy_file, eunomia_endpoint=eunomia_endpoint
            )
            middlewares.append(eunomia_mw)
            logger.info(f"Eunomia middleware enabled ({args.eunomia_type})")
        except Exception as e:
            print(f"Failed to load Eunomia middleware: {e}")
            logger.error("Failed to load Eunomia middleware", extra={"error": str(e)})
            sys.exit(1)

    mcp = FastMCP("DocumentDB", auth=auth)
    register_tools(mcp)
    register_prompts(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)

    print(f"DocumentDB MCP v{__version__}")
    print("\nStarting DocumentDB MCP Server")
    print(f"  Transport: {args.transport.upper()}")
    print(f"  Auth: {args.auth_type}")
    print(f"  Delegation: {'ON' if config['enable_delegation'] else 'OFF'}")
    print(f"  Eunomia: {args.eunomia_type}")

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
    documentdb_mcp()
