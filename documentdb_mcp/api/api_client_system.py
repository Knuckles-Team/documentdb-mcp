from typing import Any

from pymongo.errors import PyMongoError

from documentdb_mcp.api.api_client_base import (
    BaseApiClient,
    parse_json_arg,
    serialize_oid,
)


class SystemClient(BaseApiClient):
    # System
    def binary_version(self) -> str:
        try:
            info = self.client.admin.command("buildInfo")
            return info.get("version", "unknown")
        except Exception as e:
            return f"Error: {str(e)}"

    def list_databases(self) -> list[str]:
        return self.client.list_database_names()

    def run_command(
        self, database_name: str, command: dict[str, Any]
    ) -> dict[str, Any]:
        db = self.client[database_name]
        cmd = parse_json_arg(command)
        result = db.command(cmd)
        return serialize_oid(result)

    def create_database(
        self, database_name: str, initial_collection: str = "default_collection"
    ) -> str:
        db = self.client[database_name]
        try:
            db.create_collection(initial_collection)
            return f"Collection '{initial_collection}' created in database '{database_name}'"
        except PyMongoError as e:
            return f"Error creating collection: {str(e)}"

    def drop_database(self, database_name: str) -> str:
        try:
            self.client.drop_database(database_name)
            return f"Database '{database_name}' dropped"
        except PyMongoError as e:
            return f"Error dropping database: {str(e)}"

    # Collections
    def list_collections(self, database_name: str) -> list[str]:
        db = self.client[database_name]
        return db.list_collection_names()

    def create_collection(self, database_name: str, collection_name: str) -> str:
        db = self.client[database_name]
        try:
            db.create_collection(collection_name)
            return (
                f"Collection '{collection_name}' created in database '{database_name}'"
            )
        except PyMongoError as e:
            return f"Error creating collection: {str(e)}"

    def drop_collection(self, database_name: str, collection_name: str) -> str:
        db = self.client[database_name]
        try:
            db.drop_collection(collection_name)
            return f"Collection '{collection_name}' dropped from database '{database_name}'"
        except PyMongoError as e:
            return f"Error dropping collection: {str(e)}"

    def rename_collection(
        self, database_name: str, old_name: str, new_name: str
    ) -> str:
        db = self.client[database_name]
        try:
            db[old_name].rename(new_name)
            return f"Collection '{old_name}' renamed to '{new_name}'"
        except PyMongoError as e:
            return f"Error renaming collection: {str(e)}"
