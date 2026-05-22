from typing import Any

from pymongo.errors import PyMongoError

from documentdb_mcp.api.api_client_base import (
    BaseApiClient,
    parse_json_arg,
    serialize_oid,
)


class UsersClient(BaseApiClient):
    # Users
    def create_user(
        self, database_name: str, username: str, password: str, roles: list[Any]
    ) -> str:
        # CONCEPT:ECO-4.1
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
        # CONCEPT:ECO-4.1
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
