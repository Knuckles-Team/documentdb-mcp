# CONN-DOCUMENTDB-MCP-CONNECTOR-CONTENT — Requirements

Governing spec: [spec.md](spec.md).

Each row is one requirement. A row names the file it touches and the test that proves it. The generator sets each row's state in `status.json`.

| ID | Requirement | Acceptance |
|---|---|---|
| `CONN-DOCUMENTDB-MCP-CONNECTOR-CONTENT-R001` | **Default content.** `pyproject.toml` declares `documentdb-mcp` as the single `scion_sdk.connector` entry point. The server lists the packaged `skill://` and `ontology://` resources and the packaged prompts with no `content=` argument. Proving test: `tests/test_default_content_surfaces.py`. Caller chain: the documentdb-mcp console script (documentdb_mcp.mcp_server:mcp_server) builds the server with scion_sdk.connector.build_server, which loads the entry point documentdb_mcp:connector (documentdb_mcp/__init__.py:87) and serves the packaged skills, ontology and prompts. Shape: Connector in documentdb_mcp/__init__.py passes no content= argument; default content comes from documentdb_mcp/skills, ontology and prompts, verified by tests/test_default_content_surfaces.py which reads each ontology resource back byte for byte. | `resources/list` includes `skill://` and `ontology://`; `prompts/list` includes each packaged prompt. Test: `tests/test_default_content_surfaces.py::test_default_content_surfaces`. |
