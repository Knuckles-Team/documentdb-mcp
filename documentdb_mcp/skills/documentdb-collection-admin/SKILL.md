---
name: documentdb-collection-admin
skill_type: skill
description: >-
  Administer a DocumentDB (MongoDB-compatible) server via documentdb-mcp: list, create, drop and rename databases and collections, and manage database users and roles. Use to provision or tear down namespaces or manage auth principals. Do NOT use for document reads or writes (documentdb-document-crud) or analytics (documentdb-aggregation-analytics).
license: MIT
tags: [documentdb, mongodb, database, collection, admin, users, mcp]
metadata:
  author: Knuckles-Team
  version: '0.1.0'
---
# DocumentDB Collection & Database Administration

Scope: Database, collection, and user administration on a DocumentDB (MongoDB-compatible, PostgreSQL-backed) server via the documentdb-mcp MCP server — list/create/drop/rename databases and collections, and manage database users and their roles. Use when the agent must provision or tear down namespaces, enumerate the catalog, or administer auth principals. Do NOT use for reading/writing documents inside a collection (use documentdb-document-crud) or for aggregation/analytics (use documentdb-aggregation-analytics).

Structural administration of a DocumentDB server: databases, collections, and the
role-bearing users scoped to them. DocumentDB is MongoDB-compatible but runs on
PostgreSQL, so the MongoDB command/driver semantics apply.

## Steps

1. Enumerate the catalog with `documentdb_list_databases` and `documentdb_list_collections` (`database_name`).
   Verify the target namespace is or is not present.
2. Create namespaces with `documentdb_create_database` (`database_name`, `initial_collection`) or `documentdb_create_collection` (`database_name`, `collection_name`).
   Verify the collection shows in `documentdb_list_collections`.
3. Rename within one database with `documentdb_rename_collection` (`database_name`, `old_name`, `new_name`).
   Verify the new name is listed and the old one is gone.
4. Manage users with `documentdb_create_user` (`database_name`, `username`, `password`, `roles`) after approval.
   Verify with `documentdb_users_info` that the roles match, without printing the password.
5. Drop only after explicit approval with `documentdb_drop_collection` or `documentdb_drop_database` and `confirm=true`.
   Verify the namespace no longer appears in the list tools.

## Failure recovery

| Failure | Cause | Recovery |
|---------|-------|----------|
| Connection error or server-selection timeout | `MONGODB_URI`, or `MONGODB_HOST` and `MONGODB_PORT`, unset or unreachable | Set `MONGODB_URI` for the `documentdb-mcp` server and call `documentdb_list_databases` to confirm; ask the operator for the correct endpoint |
| Authorization error string | The connecting principal lacks the privilege for this command | Check the account roles with `documentdb_users_info` (`database_name`) and ask the operator for a principal with the needed role |
| Delete or drop refused | `confirm=true` was not passed, or no operator approval was given | Describe the exact target to the operator, get approval, and pass `confirm=true` |
| Database not visible after create | MongoDB creates a database lazily, without a collection | Create it with `documentdb_create_database` and an `initial_collection`, then check `documentdb_list_databases` |

## When to use
- Enumerate the catalog: list databases, list collections in a database.
- Provision namespaces: create a database (with an initial collection), create a
  collection, rename a collection.
- Tear down: drop a collection or an entire database.
- Manage auth: create / update / drop database users and inspect their roles.
- Read the server build version.

## When NOT to use
- Inserting, finding, updating, or deleting **documents** → `documentdb-document-crud`.
- `distinct` / aggregation pipelines / analytics → `documentdb-aggregation-analytics`.
- Pushing the catalog into the knowledge graph → the native `documentdb_ingest_catalog`
  tool (see Related), not the admin tools here.

## Prerequisites & environment
Connect via the `mcp-client` skill against the **`documentdb-mcp`** MCP server.

| Variable | Required | Notes |
|----------|----------|-------|
| `MONGODB_URI` | one of | Full connection URI (wins over host/port) |
| `MONGODB_HOST` | one of | Host when no URI (default `localhost`) |
| `MONGODB_PORT` | optional | Port when no URI (default `27017`) |

## Tools
| Tools | Purpose |
|-------|---------|
| `documentdb_binary_version`, `documentdb_list_databases`, `documentdb_run_command` | server version, databases, raw command |
| `documentdb_list_collections`, `documentdb_create_collection`, `documentdb_rename_collection`, `documentdb_drop_collection` | collections |
| `documentdb_create_database`, `documentdb_drop_database` | databases (drops need `confirm`) |
| `documentdb_create_user`, `documentdb_update_user`, `documentdb_users_info`, `documentdb_drop_user` | database users |

### Key parameters
- `database_name` — target database (required by nearly every tool).
- `collection_name` — target collection (create/drop collection).
- `initial_collection` — seed collection created with `create_database`.
- `old_name` / `new_name` — for `rename_collection`.
- `username` / `password` / `roles` — for the user tools; `roles` is a JSON array of
  role grants (e.g. `[{"role":"readWrite","db":"app"}]`).

## Recipes
List every database, then the collections of one:
```
documentdb_list_databases
documentdb_list_collections database_name=app
```
Provision a new database seeded with a collection:
```
documentdb_create_database database_name=analytics initial_collection=events
```
Rename then drop a collection:
```
documentdb_rename_collection database_name=app old_name=tmp new_name=archive
documentdb_drop_collection   database_name=app collection_name=archive
```
Create a scoped read/write user:
```
documentdb_create_user database_name=app username=svc password=<secret> roles=[{"role":"readWrite","db":"app"}]
```

## Gotchas
- MongoDB creates a database lazily — a database only materializes once it has a
  collection, which is why `create_database` seeds an `initial_collection`.
- `roles` must be a JSON array of role documents, not a bare string; the client parses
  JSON args but malformed roles fail server-side.
- `drop_database` is irreversible and removes all collections and documents.
- `rename_collection` is same-database only via `db[old].rename(new)`; cross-database
  moves are not supported here.
- Admin/user commands require the connecting principal to have sufficient privileges;
  otherwise the server returns an authorization error string.

## Related
- **Native KG ingestion:** `documentdb_ingest_catalog` pulls the whole catalog into the
  knowledge graph as typed `:DatabaseServer` / `:Database` / `:Collection` nodes. It is a
  plumbing tool, not part of the operational admin surface above.
- Document reads/writes → `documentdb-document-crud`; analytics →
  `documentdb-aggregation-analytics`.
