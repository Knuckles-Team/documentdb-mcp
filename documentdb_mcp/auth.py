"""Authentication module for documentdb-mcp."""

import os

import pymongo
from agent_utilities.base_utilities import get_logger

logger = get_logger(__name__)


def get_client():
    """Get authenticated client for documentdb-mcp."""
    from documentdb_mcp.api_client import DocumentDBApi

    uri = os.getenv("MONGODB_URI")
    if not uri:
        host = os.getenv("MONGODB_HOST", "localhost")
        port = os.getenv("MONGODB_PORT", "27017")
        uri = f"mongodb://{host}:{port}/"
    client: pymongo.MongoClient = pymongo.MongoClient(uri)
    return DocumentDBApi(client=client)
