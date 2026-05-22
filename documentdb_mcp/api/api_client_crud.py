from typing import Any

import pymongo
from pymongo.errors import PyMongoError

from documentdb_mcp.api.api_client_base import (
    BaseApiClient,
    parse_json_arg,
    serialize_oid,
)


class CrudClient(BaseApiClient):
    # CRUD
    def insert_one(
        self, database_name: str, collection_name: str, document: dict[str, Any]
    ) -> str:
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
