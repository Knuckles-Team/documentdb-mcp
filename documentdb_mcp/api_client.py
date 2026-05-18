import json
from typing import Any

import pymongo
from pymongo.errors import PyMongoError


def parse_json_arg(arg: Any) -> Any:
    if isinstance(arg, str):
        try:
            return json.loads(arg)
        except json.JSONDecodeError:
            return arg
    return arg


def serialize_oid(data: Any) -> Any:
    if isinstance(data, list):
        return [serialize_oid(item) for item in data]
    elif isinstance(data, dict):
        return {k: serialize_oid(v) for k, v in data.items()}
    elif hasattr(data, "__class__") and data.__class__.__name__ == "ObjectId":
        return str(data)
    else:
        return data


class DocumentDBApi:
    def __init__(self, client: pymongo.MongoClient):
        self.client = client

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

    def rename_collection(
        self, database_name: str, old_name: str, new_name: str
    ) -> str:
        db = self.client[database_name]
        try:
            db[old_name].rename(new_name)
            return f"Collection '{old_name}' renamed to '{new_name}'"
        except PyMongoError as e:
            return f"Error renaming collection: {str(e)}"

    # Users
    def create_user(
        self, database_name: str, username: str, password: str, roles: list[Any]
    ) -> str:
        db = self.client[database_name]
        try:
            parsed_roles = parse_json_arg(roles)
            db.command("createUser", username, pwd=password, roles=parsed_roles)
            return f"User '{username}' created on '{database_name}'"
        except PyMongoError as e:
            return f"Error creating user: {str(e)}"

    def drop_user(self, database_name: str, username: str) -> str:
        db = self.client[database_name]
        try:
            db.command("dropUser", username)
            return f"User '{username}' dropped from '{database_name}'"
        except PyMongoError as e:
            return f"Error dropping user: {str(e)}"

    def update_user(
        self,
        database_name: str,
        username: str,
        password: str | None = None,
        roles: list[Any] | None = None,
    ) -> str:
        db = self.client[database_name]
        update_fields: dict[str, Any] = {}
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

    def users_info(self, database_name: str, username: str) -> dict[str, Any]:
        db = self.client[database_name]
        try:
            result = db.command("usersInfo", username)
            return serialize_oid(result)
        except PyMongoError as e:
            return {"error": str(e)}

    # CRUD
    def insert_one(
        self, database_name: str, collection_name: str, document: dict[str, Any]
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        doc = parse_json_arg(document)
        try:
            result = col.insert_one(doc)
            return str(result.inserted_id)
        except PyMongoError as e:
            return f"Error inserting document: {str(e)}"

    def insert_many(
        self, database_name: str, collection_name: str, documents: list[dict[str, Any]]
    ) -> list[str]:
        db = self.client[database_name]
        col = db[collection_name]
        docs = [parse_json_arg(d) for d in documents]
        try:
            result = col.insert_many(docs)
            return [str(id) for id in result.inserted_ids]
        except PyMongoError as e:
            return [f"Error inserting documents: {str(e)}"]

    def find_one(
        self, database_name: str, collection_name: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.find_one(query)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}

    def find(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        limit: int = 20,
        skip: int = 0,
        sort: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        db = self.client[database_name]
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

    def replace_one(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        replacement: dict[str, Any],
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        repl = parse_json_arg(replacement)
        try:
            result = col.replace_one(query, repl)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error replacing document: {str(e)}"

    def update_one(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        upd = parse_json_arg(update)
        try:
            result = col.update_one(query, upd)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error updating document: {str(e)}"

    def update_many(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        upd = parse_json_arg(update)
        try:
            result = col.update_many(query, upd)
            return f"Matched: {result.matched_count}, Modified: {result.modified_count}"
        except PyMongoError as e:
            return f"Error updating documents: {str(e)}"

    def delete_one(
        self, database_name: str, collection_name: str, filter: dict[str, Any]
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.delete_one(query)
            return f"Deleted: {result.deleted_count}"
        except PyMongoError as e:
            return f"Error deleting document: {str(e)}"

    def delete_many(
        self, database_name: str, collection_name: str, filter: dict[str, Any]
    ) -> str:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.delete_many(query)
            return f"Deleted: {result.deleted_count}"
        except PyMongoError as e:
            return f"Error deleting documents: {str(e)}"

    def count_documents(
        self, database_name: str, collection_name: str, filter: dict[str, Any]
    ) -> int:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            return col.count_documents(query)
        except PyMongoError:
            return -1

    def find_one_and_update(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        update: dict[str, Any],
        return_document: str = "before",
    ) -> dict[str, Any] | None:
        db = self.client[database_name]
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

    def find_one_and_replace(
        self,
        database_name: str,
        collection_name: str,
        filter: dict[str, Any],
        replacement: dict[str, Any],
        return_document: str = "before",
    ) -> dict[str, Any] | None:
        db = self.client[database_name]
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

    def find_one_and_delete(
        self, database_name: str, collection_name: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        db = self.client[database_name]
        col = db[collection_name]
        query = parse_json_arg(filter)
        try:
            result = col.find_one_and_delete(query)
            if result:
                return serialize_oid(result)
            return None
        except PyMongoError as e:
            return {"error": str(e)}

    # Analysis
    def distinct(
        self, database_name: str, collection_name: str, key: str, filter: dict[str, Any]
    ) -> list[Any]:
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
