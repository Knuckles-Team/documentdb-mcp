---
name: documentdb-kg-ingestion
skill_type: skill
description: >-
  Mirror a DocumentDB (MongoDB-compatible) catalog and sampled documents into the knowledge graph via documentdb-mcp: servers, databases and collections as typed nodes, and sampled :Document nodes. Use to make the database estate or collection content queryable. Do NOT use to read or change documents (documentdb-document-crud) or administer databases (documentdb-collection-admin).
license: MIT
tags: [documentdb, knowledge-graph, ingestion, mcp]
metadata:
  author: Knuckles-Team
  version: '0.1.0'
---
# DocumentDB Knowledge-Graph Ingestion

Scope: Mirror a DocumentDB (MongoDB-compatible) catalog and sampled documents into the knowledge graph through the documentdb-mcp MCP server — ingest the server, databases and collections as typed nodes, and sample a collection's documents as searchable :Document nodes. Use when the agent must make the database estate or a collection's content queryable in the graph. Do NOT use to read or change documents directly (use documentdb-document-crud) or to administer databases (use documentdb-collection-admin).

## Tools
| Tool | Purpose |
|------|---------|
| `documentdb_list_databases` | The databases the caller may see (identity-scoped) |
| `documentdb_ingest_catalog` | Ingest `:DatabaseServer`, `:Database` and `:Collection` nodes with `:hostedOnServer` and `:inDatabase` links; optional `database_name` |
| `documentdb_ingest_documents` | Ingest up to `limit` documents of one collection as `:Document` nodes linked `:inCollection`; optional `filter` |

## Steps

1. Choose the scope with `documentdb_list_databases`.
   Verify the target database is listed.
2. Ingest the catalog with `documentdb_ingest_catalog`, passing `database_name` to restrict it.
   Verify `ingested` is a number, not null.
3. Ingest documents for each collection that should be searchable with `documentdb_ingest_documents` (`filter`, `limit`), keeping `limit` small.
   Verify the returned count does not exceed `limit`.
4. Spot-check a node by querying the graph for a `:Document` node linked `:inCollection`.
   Verify it exists once.

## Failure recovery

| Failure | Cause | Recovery |
|---------|-------|----------|
| `ingested` is null | No graph engine is reachable; nothing is half-written | Ask the operator to restore the engine connection through Arbora, then call `documentdb_ingest_catalog` again and check `ingested` |
| Connection error or server-selection timeout | `MONGODB_URI`, or `MONGODB_HOST` and `MONGODB_PORT`, unset or unreachable | Set `MONGODB_URI` for the `documentdb-mcp` server and call `documentdb_list_databases` to confirm; ask the operator for the correct endpoint |
| Too few documents ingested | Documents are sampled up to `limit`, or the `filter` matched little | Test the `filter` with `documentdb_find`, then raise `limit` deliberately in `documentdb_ingest_documents` |
