"""Authentication module for documentdb-mcp."""

import pymongo
from agent_utilities.base_utilities import get_logger
from agent_utilities.core.config import setting

from documentdb_mcp.api_client import DocumentDBApi

logger = get_logger(__name__)


def get_client():
    """Get authenticated client for documentdb-mcp."""
    uri = setting("MONGODB_URI", None)
    if not uri:
        host = setting("MONGODB_HOST", "localhost")
        port = setting("MONGODB_PORT", "27017")
        uri = f"mongodb://{host}:{port}/"
    # A short server-selection timeout keeps an unreachable backend from
    # hanging tool calls (or the /health probe) for pymongo's 30s default —
    # it previously masked a fully dead backend as an indefinite hang.
    client: pymongo.MongoClient = pymongo.MongoClient(
        uri, serverSelectionTimeoutMS=5000
    )
    return DocumentDBApi(client=client)
