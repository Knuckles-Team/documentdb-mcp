# CONN-DOCUMENTDB-MCP-CONNECTOR-CONTENT — Design and implementation plan

Governing spec: [spec.md](spec.md).

## Architecture

`pyproject.toml` declares `documentdb-mcp` as the connector identity. `create_mcp_server` resolves the packaged content of `documentdb_mcp` from it.
