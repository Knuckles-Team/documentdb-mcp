# Concept Registry — documentdb-mcp

> **Prefix**: `CONCEPT:DOCDB-*`
> **Version**: 0.13.0
> **Bridge**: [`CONCEPT:AU-ECO.messaging.native-backend-abstraction`](https://github.com/Knuckles-Team/scion-sdk/blob/main/docs/concepts.md) (Unified Toolkit Ingestion)

---

## Project-Specific Concepts

| Concept ID | Name | Description |
|------------|------|-------------|
| `CONCEPT:DD-OS.governance.docdb` | Analysis Operations | MCP tool domain `analysis` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-2` | Collections Operations | MCP tool domain `collections` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-3` | Crud Operations | MCP tool domain `crud` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-4` | System Information & Health | MCP tool domain `system` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-5` | Users Operations | MCP tool domain `users` — Action-routed dynamic tool registration |

## Cross-Project References (from scion-sdk)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:AU-ECO.messaging.native-backend-abstraction` | Unified Toolkit Ingestion | scion-sdk |
| `CONCEPT:AU-ORCH.adapter.hot-cache-invalidation` | Confidence-Gated Router | scion-sdk |
| `CONCEPT:AU-OS.config.secrets-authentication` | Prompt Injection Defense | scion-sdk |
| `CONCEPT:AU-OS.state.cognitive-scheduler-preemption` | Cognitive Scheduler | scion-sdk |
| `CONCEPT:AU-OS.governance.reactive-multi-axis-budget` | Guardrail Engine | scion-sdk |
| `CONCEPT:AU-OS.governance.wasm-micro-agent-sandbox` | Audit Logging | scion-sdk |
| `CONCEPT:AU-KG.query.object-graph-mapper` | Knowledge Graph Core | scion-sdk |

## Synergy with scion-sdk

This project integrates with `scion-sdk` via `CONCEPT:AU-ECO.messaging.native-backend-abstraction` (Unified Toolkit Ingestion). The `documentdb_mcp` MCP server registers its tools with the scion-sdk FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all DOCDB-* concepts.
