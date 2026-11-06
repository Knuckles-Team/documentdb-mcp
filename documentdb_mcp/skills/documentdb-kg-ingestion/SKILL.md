---
name: documentdb-kg-ingestion
skill_type: skill
description: >-
  Mirror a DocumentDB (MongoDB-compatible) catalog and sampled documents into
  the knowledge graph through the documentdb-mcp MCP server — ingest the
  server, databases and collections as typed nodes, and sample a collection's
  documents as searchable :Document nodes. Use when the agent must make the
  database estate or a collection's content queryable in the graph. Do NOT use
  to read or change documents directly (use documentdb-document-crud) or to
  administer databases (use documentdb-collection-admin).
license: MIT
tags: [documentdb, knowledge-graph, ingestion, mcp]
metadata:
  author: Knuckles-Team
  version: '0.1.0'
---
# DocumentDB Knowledge-Graph Ingestion

## Tools
| Tool | Purpose |
|------|---------|
| `documentdb_list_databases` | The databases the caller may see (identity-scoped) |
| `documentdb_ingest_catalog` | Ingest `:DatabaseServer`, `:Database` and `:Collection` nodes with `:hostedOnServer` and `:inDatabase` links; optional `database_name` |
| `documentdb_ingest_documents` | Ingest up to `limit` documents of one collection as `:Document` nodes linked `:inCollection`; optional `filter` |

## Steps
1. `documentdb_list_databases` to choose the scope.
2. `documentdb_ingest_catalog`, with `database_name` to restrict it.
3. `documentdb_ingest_documents` for each collection that should be searchable, with a `filter` and a small `limit`.

## Failure modes
- With no graph engine reachable the result reports `ingested: null`; nothing is half-written.
- Documents are sampled, not exhaustively copied; raise `limit` deliberately.
