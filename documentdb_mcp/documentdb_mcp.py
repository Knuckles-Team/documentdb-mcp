#!/usr/bin/python
# coding: utf-8
import argparse
import os
import sys
import json
import logging
from typing import List, Dict, Any, Optional

import pymongo
from pymongo.errors import PyMongoError
from fastmcp import FastMCP, Context
from fastmcp.utilities.logging import get_logger

# Initialize FastMCP server
mcp = FastMCP("DocumentDB")

# Global logger
logger = get_logger(name="DocumentDB")

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
            port = os.environ.get("MONGODB_PORT", "27017")
            uri = f"mongodb://{host}:{port}/"
        
        logger.info(f"Connecting to DocumentDB/MongoDB at {uri}")
        try:
            _client = pymongo.MongoClient(uri)
            # Connectivity check
            _client.admin.command('ping')
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
    elif hasattr(data, '__class__') and data.__class__.__name__ == 'ObjectId':
        return str(data)
    else:
        return data

# ==================================================================================
# Utility Functions
# ==================================================================================

@mcp.tool()
def binary_version() -> str:
    """Get the binary version of the server (using buildInfo)."""
    try:
        client = get_client()
        info = client.admin.command("buildInfo")
        return info.get("version", "unknown")
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def list_databases() -> List[str]:
    """List all databases in the connected DocumentDB/MongoDB instance."""
    client = get_client()
    return client.list_database_names()

@mcp.tool()
def run_command(database_name: str, command: Dict[str, Any]) -> Dict[str, Any]:
    """Run a raw command against the database."""
    client = get_client()
    db = client[database_name]
    cmd = parse_json_arg(command)
    result = db.command(cmd)
    return serialize_oid(result)

# ==================================================================================
# Collection Management
# ==================================================================================

@mcp.tool()
def list_collections(database_name: str) -> List[str]:
    """List all collections in a specific database."""
    client = get_client()
    db = client[database_name]
    return db.list_collection_names()

@mcp.tool()
def create_collection(database_name: str, collection_name: str) -> str:
    """Create a new collection in the specified database."""
    client = get_client()
    db = client[database_name]
    try:
        db.create_collection(collection_name)
        return f"Collection '{collection_name}' created in database '{database_name}'"
    except PyMongoError as e:
        return f"Error creating collection: {str(e)}"

@mcp.tool()
def drop_collection(database_name: str, collection_name: str) -> str:
    """Drop a collection from the specified database."""
    client = get_client()
    db = client[database_name]
    try:
        db.drop_collection(collection_name)
        return f"Collection '{collection_name}' dropped from database '{database_name}'"
    except PyMongoError as e:
        return f"Error dropping collection: {str(e)}"

@mcp.tool()
def create_database(database_name: str, initial_collection: str = "test") -> str:
    """Explicitly create a database by creating a collection in it (MongoDB creates DBs lazily)."""
    # This maps loosely to create_database, but typically we just start using it.
    return create_collection(database_name, initial_collection)

@mcp.tool()
def drop_database(database_name: str) -> str:
    """Drop a database."""
    client = get_client()
    try:
        client.drop_database(database_name)
        return f"Database '{database_name}' dropped"
    except PyMongoError as e:
        return f"Error dropping database: {str(e)}"

@mcp.tool()
def rename_collection(database_name: str, old_name: str, new_name: str) -> str:
    """Rename a collection."""
    client = get_client()
    db = client[database_name]
    try:
        db[old_name].rename(new_name)
        return f"Collection '{old_name}' renamed to '{new_name}'"
    except PyMongoError as e:
        return f"Error renaming collection: {str(e)}"

# ==================================================================================
# User Management
# ==================================================================================

@mcp.tool()
def create_user(database_name: str, username: str, password: str, roles: List[Any]) -> str:
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

@mcp.tool()
def drop_user(database_name: str, username: str) -> str:
    """Drop a user from the specified database."""
    client = get_client()
    db = client[database_name]
    try:
        db.command("dropUser", username)
        return f"User '{username}' dropped from '{database_name}'"
    except PyMongoError as e:
        return f"Error dropping user: {str(e)}"

@mcp.tool()
def update_user(database_name: str, username: str, password: Optional[str] = None, roles: Optional[List[Any]] = None) -> str:
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

@mcp.tool()
def users_info(database_name: str, username: str) -> Dict[str, Any]:
    """Get information about a user."""
    client = get_client()
    db = client[database_name]
    try:
        result = db.command("usersInfo", username)
        return serialize_oid(result)
    except PyMongoError as e:
        return {"error": str(e)}

# ==================================================================================
# CRUD Operations
# ==================================================================================

@mcp.tool()
def insert_one(database_name: str, collection_name: str, document: Dict[str, Any]) -> str:
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

@mcp.tool()
def insert_many(database_name: str, collection_name: str, documents: List[Dict[str, Any]]) -> List[str]:
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

@mcp.tool()
def find_one(database_name: str, collection_name: str, filter: Dict[str, Any] = {}) -> Optional[Dict[str, Any]]:
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

@mcp.tool()
def find(database_name: str, collection_name: str, filter: Dict[str, Any] = {}, limit: int = 20, skip: int = 0, sort: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
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

@mcp.tool()
def replace_one(database_name: str, collection_name: str, filter: Dict[str, Any], replacement: Dict[str, Any]) -> str:
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

@mcp.tool()
def update_one(database_name: str, collection_name: str, filter: Dict[str, Any], update: Dict[str, Any]) -> str:
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

@mcp.tool()
def update_many(database_name: str, collection_name: str, filter: Dict[str, Any], update: Dict[str, Any]) -> str:
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

@mcp.tool()
def delete_one(database_name: str, collection_name: str, filter: Dict[str, Any]) -> str:
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

@mcp.tool()
def delete_many(database_name: str, collection_name: str, filter: Dict[str, Any]) -> str:
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

@mcp.tool()
def count_documents(database_name: str, collection_name: str, filter: Dict[str, Any] = {}) -> int:
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

@mcp.tool()
def distinct(database_name: str, collection_name: str, key: str, filter: Dict[str, Any] = {}) -> List[Any]:
    """Find distinct values for a key."""
    client = get_client()
    db = client[database_name]
    col = db[collection_name]
    query = parse_json_arg(filter)
    try:
        return col.distinct(key, query)
    except PyMongoError as e:
        return [f"Error getting distinct values: {str(e)}"]

@mcp.tool()
def aggregate(database_name: str, collection_name: str, pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

@mcp.tool()
def find_one_and_update(database_name: str, collection_name: str, filter: Dict[str, Any], update: Dict[str, Any], return_document: str = "before") -> Optional[Dict[str, Any]]:
    """Finds a single document and updates it. return_document: 'before' or 'after'."""
    client = get_client()
    db = client[database_name]
    col = db[collection_name]
    query = parse_json_arg(filter)
    upd = parse_json_arg(update)
    ret_doc = pymongo.ReturnDocument.AFTER if return_document.lower() == "after" else pymongo.ReturnDocument.BEFORE
    try:
        result = col.find_one_and_update(query, upd, return_document=ret_doc)
        if result:
            return serialize_oid(result)
        return None
    except PyMongoError as e:
        return {"error": str(e)}

@mcp.tool()
def find_one_and_replace(database_name: str, collection_name: str, filter: Dict[str, Any], replacement: Dict[str, Any], return_document: str = "before") -> Optional[Dict[str, Any]]:
    """Finds a single document and replaces it. return_document: 'before' or 'after'."""
    client = get_client()
    db = client[database_name]
    col = db[collection_name]
    query = parse_json_arg(filter)
    repl = parse_json_arg(replacement)
    ret_doc = pymongo.ReturnDocument.AFTER if return_document.lower() == "after" else pymongo.ReturnDocument.BEFORE
    try:
        result = col.find_one_and_replace(query, repl, return_document=ret_doc)
        if result:
            return serialize_oid(result)
        return None
    except PyMongoError as e:
        return {"error": str(e)}

@mcp.tool()
def find_one_and_delete(database_name: str, collection_name: str, filter: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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


def documentdb_mcp():
    parser = argparse.ArgumentParser(description="DocumentDB MCP Server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "http", "sse"],
        help="Transport method (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port number for HTTP transport (default: 8000)",
    )
    # Add other args from original skeleton if needed for auth/etc, 
    # but for now we focus on core functionality.
    
    args = parser.parse_args()
    
    if args.transport == "http":
        mcp.run("0.0.0.0", args.port)
    elif args.transport == "sse":
        mcp.run_sse("0.0.0.0", args.port)
    else:
        mcp.run_stdio()

if __name__ == "__main__":
    documentdb_mcp()
