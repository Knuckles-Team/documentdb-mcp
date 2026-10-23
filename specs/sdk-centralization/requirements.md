# CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION — Requirements

Governing spec: [spec.md](spec.md).

Each row is one requirement. A child row `.n` is one five-minute unit of work. A row names the file it touches and the test that proves it. The generator sets each row's state in `status.json`.

| ID | Requirement | Acceptance |
|---|---|---|
| `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001` | **Capabilities come from the SDK (rollup).** The connector must use the SDK for HTTP, retry, TLS and optional dependencies. Children `.1` to `.2` deliver it. | See each child. |
| `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.1` | **Database driver from the SDK.** The package must take the MongoDB driver from the SDK `db` extra and must not pin `pymongo` itself (`SDK-CENTRALIZED-CAPABILITIES-R040`). The pin must be absent from `pyproject.toml` and `requirements.txt`. Proving test: `tests/test_sdk_dependencies.py::test_driver_comes_from_the_sdk_db_extra`. | No file pins `pymongo` and the dependencies request `agent-connector-sdk[mcp,db]`. |
| `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.2` | **SDK floor.** The package must depend on the SDK at the latest release floor, `0.3.11` or later (`SDK-CENTRALIZED-CAPABILITIES-R040`). Proving test: `tests/test_sdk_dependencies.py::test_sdk_floor_is_current`. | Every SDK requirement has a floor of `0.3.11` or later. |
