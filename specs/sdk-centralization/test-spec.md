# CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION — Test specification

Governing spec: [spec.md](spec.md).

| Test ID | Requirement | Level | Setup and input | Expected observation | Evidence |
|---|---|---|---|---|---|
| T-001 | `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001` | Unit | Every child row. | See each child. |  |
| T-002 | `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.1` | Unit | `tests/test_sdk_dependencies.py::test_driver_comes_from_the_sdk_db_extra` | No file pins `pymongo` and the dependencies request `agent-connector-sdk[mcp,db]`. |  |
| T-003 | `CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.2` | Unit | `tests/test_sdk_dependencies.py::test_sdk_floor_is_current` | Every SDK requirement has a floor of `0.3.11` or later. |  |
