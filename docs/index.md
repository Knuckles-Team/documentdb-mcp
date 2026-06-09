# documentdb-mcp

DocumentDB **MCP Server + A2A Agent** for the agent-utilities ecosystem — a typed,
deterministic tool surface over **DocumentDB**, the MongoDB-compatible open-source
document database built on PostgreSQL.

!!! info "Official documentation"
    This site is the canonical reference for `documentdb-mcp`, maintained alongside
    every release.

[![PyPI](https://img.shields.io/pypi/v/documentdb-mcp)](https://pypi.org/project/documentdb-mcp/)
![MCP Server](https://badge.mcpx.dev?type=server 'MCP Server')
[![License](https://img.shields.io/pypi/l/documentdb-mcp)](https://github.com/Knuckles-Team/documentdb-mcp/blob/main/LICENSE)
[![GitHub](https://img.shields.io/badge/source-GitHub-181717?logo=github)](https://github.com/Knuckles-Team/documentdb-mcp)

## Overview

`documentdb-mcp` wraps the DocumentDB / MongoDB wire-protocol surface with granular,
action-routed MCP tools and a Pydantic-AI graph agent. It provides:

- **`DocumentDBApi`** — a `pymongo`-backed client that groups system, collections,
  users, CRUD, and analysis operations behind one tolerant facade.
- **Action-routed MCP tools** — five togglable tool modules (system, collections,
  users, CRUD, analysis) that minimize token overhead in an LLM context.
- **An integrated A2A agent** — a Pydantic-AI graph agent (console script
  `documentdb-agent`) that speaks the Agent Control Protocol and exposes a web UI.

The server connects to any MongoDB-compatible endpoint, so it operates against
DocumentDB or a standard MongoDB deployment interchangeably.

## Explore the documentation

<div class="grid cards" markdown>

- :material-rocket-launch: **[Installation](installation.md)** — pip, source, extras, and the prebuilt Docker image.
- :material-server-network: **[Deployment](deployment.md)** — run the MCP server and agent, Docker Compose, Caddy + Technitium.
- :material-console: **[Usage](usage.md)** — the MCP tools, the `DocumentDBApi` client, and the CLI.
- :material-database-cog: **[Backing Platform](platform.md)** — deploy DocumentDB with Docker.
- :material-sitemap: **[Overview](overview.md)** — ecosystem role, tool modules, and configuration.
- :material-tag-multiple: **[Concepts](concepts.md)** — the `CONCEPT:DOCDB-*` registry.

</div>

## Quick start

```bash
pip install documentdb-mcp
documentdb-mcp                   # stdio MCP server (default transport)
```

Connect it to a DocumentDB / MongoDB endpoint:

```bash
export MONGODB_URI=mongodb://localhost:27017/
documentdb-mcp --transport streamable-http --host 0.0.0.0 --port 8000
```

See **[Installation](installation.md)** and **[Deployment](deployment.md)** for the
full matrix (PyPI extras, Docker image, all transports, the agent server, reverse
proxy, DNS).
