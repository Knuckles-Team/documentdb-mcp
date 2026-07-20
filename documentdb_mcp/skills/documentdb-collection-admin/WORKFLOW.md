# Documentdb Collection Admin

Database, collection, and user administration on a DocumentDB (MongoDB-compatible, PostgreSQL-backed) server via the documentdb-mcp MCP server — list/create/drop/rename databases and collections, and manage database users and their roles. Use when the agent must provision or tear down namespaces, enumerate the catalog, or administer auth principals. Do NOT use for reading/writing documents inside a collection (use documentdb-document-crud) or for aggregation/analytics (use documentdb-aggregation-analytics).

# DocumentDB Collection & Database Administration

Structural administration of a DocumentDB server: databases, collections, and the
role-bearing users scoped to them. DocumentDB is MongoDB-compatible but runs on
PostgreSQL, so the MongoDB command/driver semantics apply.

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

`MCP_TOOL_MODE` (`condensed`|`verbose`|`both`) selects the condensed action-routed
surface (used below) vs. the one-to-one verbose tools.

## Tools & actions
| Condensed tool | Actions |
|----------------|---------|
| `documentdb_system` | `binary_version`, `list_databases`, `run_command` |
| `documentdb_collections` | `list_collections`, `create_collection`, `drop_collection`, `create_database`, `drop_database`, `rename_collection` |
| `documentdb_users` | `create_user`, `drop_user`, `update_user`, `users_info` |

### Key parameters
- `database_name` — target database (required by nearly every action).
- `collection_name` — target collection (create/drop collection).
- `initial_collection` — seed collection created with `create_database`.
- `old_name` / `new_name` — for `rename_collection`.
- `username` / `password` / `roles` — for the user actions; `roles` is a JSON array of
  role grants (e.g. `[{"role":"readWrite","db":"app"}]`).

## Recipes
List every database, then the collections of one:
```
documentdb_system   action=list_databases
documentdb_collections action=list_collections database_name=app
```
Provision a new database seeded with a collection:
```
documentdb_collections action=create_database database_name=analytics initial_collection=events
```
Rename then drop a collection:
```
documentdb_collections action=rename_collection database_name=app old_name=tmp new_name=archive
documentdb_collections action=drop_collection   database_name=app collection_name=archive
```
Create a scoped read/write user:
```
documentdb_users action=create_user database_name=app username=svc password=<secret> roles=[{"role":"readWrite","db":"app"}]
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
