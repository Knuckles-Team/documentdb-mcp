---
name: documentdb-mcp-development
skill_type: skill
domain: development
description: >-
  Develop, test, gate, and release the documentdb-mcp connector while
  preserving its SDK-owned client boundary, action-routed tools, knowledge
  graph ingestion, packaged resources, and shared publication contracts.
license: MIT
tags: [documentdb, development, connector, mcp, mongodb, testing, release]
tier: repository
metadata:
  author: Knuckles-Team
  version: '0.1.0'
---

# DocumentDB MCP Development

Use this skill for changes inside `documentdb-mcp`. The rapid-delivery row is
the central `PIPE-CONNSPEC-R116.4` criterion; read it with `AGENTS.md` and the
focused tests before changing a connector surface. This repository owns the
DocumentDB calls, mappings, MCP tools, and packaged connector content. Shared
transport, identity, ingestion, and publication contracts stay with their
owning packages.

## Repository and runtime map

- `documentdb_mcp/__init__.py` is the SDK `Connector` entry point. It composes
  `DocumentDBApi`, `get_client`, and the legacy health-route registration.
- `documentdb_mcp/api_client.py` is the public `DocumentDBApi` facade. The
  domain mixins under `documentdb_mcp/api/` own system, collection, user,
  document CRUD, and analytics calls; keep one facade and reuse those methods.
- `documentdb_mcp/auth.py` reads `MONGODB_URI`, or the `MONGODB_HOST` and
  `MONGODB_PORT` fallback, and creates the SDK-backed Mongo client with the
  bounded server-selection timeout. Keep credentials and endpoints in injected
  configuration.
- `documentdb_mcp/mcp_server.py` preserves the legacy CLI and `/health` route
  while `documentdb_mcp/tools/` registers the action-routed system,
  collections, users, CRUD, analysis, and knowledge-graph tools.
  The public tool names are `documentdb_system`, `documentdb_collections`,
  `documentdb_users`, `documentdb_crud`, `documentdb_analysis`,
  `documentdb_ingest_catalog`, and `documentdb_ingest_documents`.
- `documentdb_mcp/kg_ingest.py` maps catalog and document samples into typed
  SDK ingestion records. `documentdb_mcp/connector_sources.py` owns the live
  `connector://resources` declaration, while `documentdb_mcp/ontology/` owns
  the packaged DocumentDB vocabulary and mappings.
- `documentdb_mcp/skills/**`, `prompts/**`, `ontology/**`, `connectors/**`,
  `agent_data/**`, and `mcp_config.json` are package resources. Preserve the
  existing `skills/**` package-data rule so wheels and sdists carry the same
  content.

## Connector boundary and safety

DocumentDB is the external database system of record. The connector owns its
MongoDB-compatible calls and maps records for SDK ingestion; it does not become
the durable knowledge graph or an orchestration/server authority. Preserve the
`documentdb-mcp` connector identity, SDK `Connector` composition, source IDs,
typed ingestion node IDs, and the existing 30-tool surface.

Keep `MONGODB_URI`, `MONGODB_HOST`, `MONGODB_PORT`, credentials, tenant data,
and raw records out of source, logs, fixtures, and skill content. Use the SDK
transport and configuration helpers; never add a TLS-verification bypass or a
second HTTP/MCP/client implementation. Mock database calls in local tests and
never require a live DocumentDB server for a gate.

## Rapid delivery: the 5-minute contract

1. Read the owning requirement, this skill, `AGENTS.md`, and the directly
   bound tests before editing a connector surface. Central pipelines owns
   `PIPE-CONNSPEC-R116.4`; do not invent a local status row for it.
2. Trace changed behavior through the SDK `Connector`, `get_client`, the
   `DocumentDBApi` facade, the action registrar, source declarations, ontology,
   and package-data boundary. Reuse existing API methods and action dispatch;
   do not create a second connector, client, or tool route.
3. Make the smallest connector-owned change. Preserve database and collection
   scoping, action names, response shapes, identity filtering, source IDs,
   typed ingestion mappings, and the health/CLI configuration behavior.
4. Run the directly bound mock or content test with the locked environment,
   then run the normal repository hooks. Never bypass a failing hook, contact a
   live database, or place secrets in a test fixture.
5. When package content changes, inspect the wheel and sdist for the intended
   `documentdb_mcp/skills/**`, prompt, ontology, connector, and config files.
   Change the project version and `uv.lock` together only for a real release;
   keep the `CHANGELOG.md` entry on that same version.
6. Treat generated status and Pages as separate evidence. Pipelines owns
   `specs/**/status.json`; do not hand-edit it or claim a verified/public
   release from source tests, workflow YAML, or a local build alone.

## Focused validation

For a skill or package-data change, verify frontmatter, the required rapid
contract heading, source-backed paths, package-data inclusion, and coherent
release metadata without importing a live DocumentDB client. For API or MCP
changes, use the existing mock clients and test the smallest affected tool
surface, including refusal and malformed-input behavior where applicable.

From the repository root:

```bash
uv sync --locked
uv run --locked --extra test pytest -q tests/test_documentdb_development_skill.py
uvx pre-commit run --all-files
```

The canonical `.pre-commit-config.yaml` delegates connector-standard, secrets,
spec, tests-fast, and dependency-readiness checks to
`Knuckles-Team/pipelines` at `rev: main`. Do not copy those hooks locally or
bypass a failing check.

## Publication and Pages

`.github/workflows/pipeline.yml` delegates package publication to
`Knuckles-Team/pipelines/.github/workflows/python_pipeline.yml@main` with
`connector: true`, then invokes
`Knuckles-Team/pipelines/.github/workflows/container_pipeline.yml@main` with
`render_connector: true`. `.github/workflows/pages.yml` delegates docs and the
spec dashboard to `pages_pipeline.yml@main` with the checked-in dashboard
configuration. Keep these existing caller contracts intact; do not add a
second publisher or commit generated release artifacts.

Work in a real worktree based on `origin/main`. Inspect the complete diff,
stage only reviewed paths, and verify `git status --short` after every gate.
Never use `git stash`, `git add -A`, `git add .`, or a live DocumentDB
endpoint. Keep this slice focused on the packaged development skill
and its proof for `PIPE-CONNSPEC-R116.4`.
