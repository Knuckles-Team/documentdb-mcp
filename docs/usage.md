# Usage — API / CLI / MCP

`documentdb-mcp` exposes the same capability three ways: as **MCP tools** an agent
calls, as a **Python API** (`DocumentDBApi`) you import, and as a **CLI** / agent
server. The ecosystem role and the tool modules are covered in [Overview](overview.md).

## As an MCP server

Once [deployed](deployment.md), the server registers five action-routed tool modules.
Each module is togglable with its environment switch (all default to `True`):

| Module | Env switch | Action-routed methods |
|---|---|---|
| System | `SYSTEMTOOL` | `binary_version`, `list_databases`, `run_command`, `create_database`, `drop_database` |
| Collections | `COLLECTIONSTOOL` | `list_collections`, `create_collection`, `drop_collection`, `rename_collection` |
| Users | `USERSTOOL` | `create_user`, `drop_user`, `update_user`, `users_info` |
| CRUD | `CRUDTOOL` | `find`, `find_one`, `insert_one`, `insert_many`, `update_one`, `update_many`, `replace_one`, `delete_one`, `delete_many`, `count_documents`, `find_one_and_update`, `find_one_and_replace`, `find_one_and_delete` |
| Analysis | `ANALYSISTOOL` | `distinct`, `aggregate` |

Example agent prompts that map onto these tools:

- *"List the databases on this server"* → System (`list_databases`)
- *"Find the 10 most recent orders for customer 42"* → CRUD (`find`)
- *"How many documents match status = active in the orders collection?"* → CRUD (`count_documents`)
- *"What are the distinct values of `country` in the users collection?"* → Analysis (`distinct`)

## As a Python API

`DocumentDBApi` is a `pymongo`-backed facade that groups the system, collections,
users, CRUD, and analysis operations. Build one straight from the environment with
`get_client()`:

```python
from documentdb_mcp.auth import get_client

api = get_client()        # reads MONGODB_URI / MONGODB_HOST / MONGODB_PORT
```

…or construct it explicitly from a `pymongo` client:

```python
import pymongo
from documentdb_mcp.api_client import DocumentDBApi

api = DocumentDBApi(client=pymongo.MongoClient("mongodb://localhost:27017/"))

# System reads
print(api.binary_version())             # server build version
print(api.list_databases())             # ["admin", "documentation_db", ...]
print(api.list_collections("documentation_db"))

# CRUD reads — ObjectIds are serialized to strings
docs = api.find("documentation_db", "orders", {"status": "active"}, limit=10)
one = api.find_one("documentation_db", "orders", {"_id": "65a..."})
n = api.count_documents("documentation_db", "orders", {"status": "active"})

# Analysis reads
countries = api.distinct("documentation_db", "users", "country", {})
pipeline = [{"$group": {"_id": "$status", "n": {"$sum": 1}}}]
summary = api.aggregate("documentation_db", "orders", pipeline)
```

### Writes

Write operations are available on the same client; each returns a status string:

```python
api.insert_one("documentation_db", "orders", {"status": "active", "total": 42})
api.update_one("documentation_db", "orders", {"_id": "65a..."}, {"$set": {"status": "shipped"}})
api.delete_one("documentation_db", "orders", {"_id": "65a..."})
```

## As a CLI / agent

The MCP server console script doubles as a CLI entry point, and the package ships a
Pydantic-AI graph agent:

```bash
# Run the MCP server (default stdio transport)
documentdb-mcp

# Run the integrated agent server (web UI + ACP) — see Deployment
documentdb-agent --provider openai --model-id gpt-4o
```

Each connector reads its connection settings from the environment (see
[`.env.example`](https://github.com/Knuckles-Team/documentdb-mcp/blob/main/.env.example))
and the server remains inactive when no reachable endpoint is configured.
