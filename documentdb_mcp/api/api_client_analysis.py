from typing import Any

from pymongo.errors import PyMongoError

from documentdb_mcp.api.api_client_base import (
    BaseApiClient,
    parse_json_arg,
    serialize_oid,
)


class AnalysisClient(BaseApiClient):
    # Analysis
    def distinct(
        self, database_name: str, collection_name: str, key: str, filter: dict[str, Any]
    ) -> list[Any]:
        # CONCEPT:ECO-4.1
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            return col.distinct(key, query)
        except PyMongoError as e:
            return [f"Error getting distinct values: {str(e)}"]

    def aggregate(
        self, database_name: str, collection_name: str, pipeline: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        # CONCEPT:ECO-4.1
        db = self.client[database_name]
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
