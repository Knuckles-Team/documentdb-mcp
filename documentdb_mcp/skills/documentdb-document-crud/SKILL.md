---
name: documentdb-document-crud
skill_type: skill
description: >-
  Document create/read/update/delete operations on a DocumentDB (MongoDB-compatible,
  PostgreSQL-backed) collection via the documentdb-mcp MCP server — insert one/many,
  find with filter/sort/skip/limit, update/replace one/many, delete, count, and the
  atomic find-and-modify variants. Use when the agent must read or mutate the documents
  inside a known database + collection. Do NOT use for creating/dropping the collection
  itself or managing users (use documentdb-collection-admin) or for aggregation
  pipelines and distinct/analytics (use documentdb-aggregation-analytics).
license: MIT
tags: [documentdb, mongodb, crud, documents, query, mcp]
metadata:
  author: Genius
  version: '0.1.0'
---
# DocumentDB Document CRUD

Row-level document operations against a specific `database_name` + `collection_name`
using MongoDB filter/update semantics.

## When to use
- Insert one or many documents.
- Query: `find_one` / `find` with a filter, plus `sort`, `skip`, `limit`.
- Mutate: `update_one` / `update_many` (with update operators), `replace_one`.
- Remove: `delete_one` / `delete_many`; `count_documents` for cardinality.
- Atomic read-modify-write: `find_one_and_update` / `find_one_and_replace` /
  `find_one_and_delete`.

## When NOT to use
- Creating/dropping/renaming the collection or database, or user management →
  `documentdb-collection-admin`.
- `distinct` values or `$group`/`$match` aggregation pipelines →
  `documentdb-aggregation-analytics`.
- Bulk-loading a collection into the knowledge graph → the native
  `documentdb_ingest_documents` tool (see Related).

## Prerequisites & environment
Connect via the `mcp-client` skill against the **`documentdb-mcp`** MCP server.

| Variable | Required | Notes |
|----------|----------|-------|
| `MONGODB_URI` | one of | Full connection URI (wins over host/port) |
| `MONGODB_HOST` | one of | Host when no URI (default `localhost`) |
| `MONGODB_PORT` | optional | Port when no URI (default `27017`) |

`MCP_TOOL_MODE` (`condensed`|`verbose`|`both`) selects the condensed action-routed
surface vs. the one-to-one verbose tools.

## Tools & actions
| Condensed tool | Actions |
|----------------|---------|
| `documentdb_crud` | `insert_one`, `insert_many`, `find_one`, `find`, `replace_one`, `update_one`, `update_many`, `delete_one`, `delete_many`, `count_documents`, `find_one_and_update`, `find_one_and_replace`, `find_one_and_delete` |

### Key parameters
- `database_name` / `collection_name` — required for every action.
- `document` / `documents` — the payload(s) for inserts.
- `filter` — a MongoDB query document (e.g. `{"status":"active"}`).
- `update` — a MongoDB update document with operators (e.g. `{"$set":{"seen":true}}`).
- `replacement` — full replacement document (no operators) for replace/find-and-replace.
- `limit` / `skip` / `sort` — `find` paging/ordering (`sort` is a list of `[field, dir]`).
- `return_document` — `"before"` (default) or `"after"` for find-and-modify.

## Recipes
Insert and read back:
```
documentdb_crud action=insert_one  database_name=app collection_name=users document={"email":"a@b.co","active":true}
documentdb_crud action=find_one    database_name=app collection_name=users filter={"email":"a@b.co"}
```
Paged, sorted query:
```
documentdb_crud action=find database_name=app collection_name=events filter={"level":"error"} sort=[["ts",-1]] limit=25 skip=0
```
Update with an operator, then count:
```
documentdb_crud action=update_many database_name=app collection_name=jobs filter={"state":"queued"} update={"$set":{"state":"running"}}
documentdb_crud action=count_documents database_name=app collection_name=jobs filter={"state":"running"}
```
Atomic claim (return the updated doc):
```
documentdb_crud action=find_one_and_update database_name=app collection_name=jobs filter={"state":"queued"} update={"$set":{"state":"claimed"}} return_document=after
```

## Gotchas
- `update`/`update_many` require MongoDB **update operators** (`$set`, `$inc`, …); a
  bare document raises a server error — use `replace_one` for a full-document swap.
- `find` defaults to `limit=20`; pass an explicit `limit` (or `0` for unbounded, which
  is slow) for exhaustive reads.
- `_id` (ObjectId) is serialized to a **string** in results; pass it back as a string in
  filters against `_id`.
- `count_documents` returns `-1` on error (it never raises), so treat negatives as
  failures, not empty collections.
- Filters/updates may be passed as JSON strings; the client parses them, but an
  unparseable string is sent through verbatim and will fail.

## Related
- **Native KG ingestion:** `documentdb_ingest_documents` samples a collection and pushes
  each row as a `:Document` node linked `:inCollection`. Use it for KG hydration, not for
  operational reads/writes above.
- Namespace/user admin → `documentdb-collection-admin`; aggregation →
  `documentdb-aggregation-analytics`.
