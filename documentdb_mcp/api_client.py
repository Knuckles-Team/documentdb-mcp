import pymongo

from documentdb_mcp.api.api_client_analysis import AnalysisClient
from documentdb_mcp.api.api_client_base import parse_json_arg, serialize_oid
from documentdb_mcp.api.api_client_crud import CrudClient
from documentdb_mcp.api.api_client_system import SystemClient
from documentdb_mcp.api.api_client_users import UsersClient

# Expose helpers for backwards compatibility
__all__ = ["DocumentDBApi", "parse_json_arg", "serialize_oid"]


class DocumentDBApi(
    SystemClient,
    UsersClient,
    CrudClient,
    AnalysisClient,
):
    def __init__(self, client: pymongo.MongoClient):
        super().__init__(client=client)
