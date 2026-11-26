---
name: documentdb-aggregation-analytics
skill_type: skill
description: >-
  Read-only analytics on a DocumentDB (MongoDB-compatible) collection via documentdb-mcp: run aggregation pipelines and fetch distinct field values. Use to summarize, group or profile documents rather than fetch rows. Do NOT use for plain document reads or writes (documentdb-document-crud) or admin (documentdb-collection-admin).
license: MIT
tags: [documentdb, mongodb, aggregation, analytics, distinct, mcp]
metadata:
  author: Knuckles-Team
  version: '0.1.0'
---
# DocumentDB Aggregation & Analytics

Scope: Read-only analytics on a DocumentDB (MongoDB-compatible, PostgreSQL-backed) collection via the documentdb-mcp MCP server — run aggregation pipelines ($match/$group/$sort/…) and fetch distinct field values. Use when the agent must summarize, group, or profile documents rather than fetch individual rows. Do NOT use for plain document reads/writes (use documentdb-document-crud) or for creating/dropping collections and users (use documentdb-collection-admin).

Server-side summarization over a collection: MongoDB aggregation pipelines and distinct
value enumeration. These stay read-only and push the computation to the server.

## Steps

1. Confirm the target with `documentdb_list_databases` and `documentdb_list_collections` (`database_name`).
   Verify the collection is listed.
2. For distinct values, call `documentdb_distinct` (`database_name`, `collection_name`, `key`, `filter`).
   Verify the result is a list and not an error string.
3. For summaries, build the `pipeline` as a list of stage documents with an early `$match`, and call `documentdb_aggregate`.
   Verify the first element is not an `error` document.
4. Avoid write stages such as `$out` and `$merge` without operator approval.
   Verify the pipeline contains none before calling.
5. Report the result with the pipeline used.
   Verify the numbers by a sample check with `documentdb_count_documents` (`database_name`, `collection_name`, `filter`).

## Failure recovery

| Failure | Cause | Recovery |
|---------|-------|----------|
| Connection error or server-selection timeout | `MONGODB_URI`, or `MONGODB_HOST` and `MONGODB_PORT`, unset or unreachable | Set `MONGODB_URI` for the `documentdb-mcp` server and call `documentdb_list_databases` to confirm; ask the operator for the correct endpoint |
| Result is `[{"error": ...}]` | Malformed pipeline, a single stage not wrapped in a list, or an unknown field | Fix the `pipeline` to a list of stage documents, test it with a leading `$limit` stage, and call `documentdb_aggregate` again |
| Aggregation is slow | Large unindexed `$group` or `$sort` stage | Add an early `$match` on an indexed field and a `$limit` to the `pipeline` |

## When to use
- Group/roll-up metrics with an aggregation pipeline (`$match`, `$group`, `$sort`,
  `$project`, `$limit`, …).
- Enumerate the distinct values of a field (optionally filtered).
- Profile a collection (counts per category, top-N, min/max) without pulling raw rows.

## When NOT to use
- Fetching or mutating individual documents → `documentdb-document-crud`.
- Structural changes (create/drop/rename collection, users) →
  `documentdb-collection-admin`.
- Write-stage pipelines (`$out` / `$merge`): the tool returns results, treat any
  materialization as an admin action and confirm intent first.

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
| `documentdb_distinct`, `documentdb_aggregate` | distinct values and aggregation pipelines |

### Key parameters
- `database_name` / `collection_name` — required.
- `key` + `filter` — for `distinct` (field name + optional MongoDB filter).
- `pipeline` — for `aggregate`: a list of pipeline stage documents.

## Recipes
Distinct values of a field among active docs:
```
documentdb_distinct database_name=app collection_name=users key=country filter={"active":true}
```
Count errors per service, top 5:
```
documentdb_aggregate database_name=app collection_name=events pipeline=[{"$match":{"level":"error"}},{"$group":{"_id":"$service","n":{"$sum":1}}},{"$sort":{"n":-1}},{"$limit":5}]
```
Average order value by status:
```
documentdb_aggregate database_name=shop collection_name=orders pipeline=[{"$group":{"_id":"$status","avg":{"$avg":"$total"}}}]
```

## Gotchas
- `pipeline` is a **list of stage documents**; a single object (not wrapped in a list)
  is invalid.
- On a pipeline error the tool returns `[{"error": "..."}]` rather than raising —
  inspect the first element before trusting results.
- `distinct` returns a plain list; on error it returns a one-element list whose string
  starts with `Error getting distinct values:`.
- ObjectId values in `$group` `_id` are serialized to strings in the output.
- Large unindexed `$group`/`$sort` stages can be slow — pre-filter with an early
  `$match` on an indexed field.

## Related
- Row-level reads/writes → `documentdb-document-crud`.
- Namespace/user admin → `documentdb-collection-admin`.
- Aggregation results worth persisting for semantic search can be pushed via the native
  `documentdb_ingest_documents` tool.
