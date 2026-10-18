# Concept Registry — documentdb-mcp

> **Prefix**: `CONCEPT:DOCDB-*`
> **Version**: 0.13.0
> **Bridge**: [`CONCEPT:AU-ECO.messaging.native-backend-abstraction`](https://github.com/Knuckles-Team/agent-connector-sdk/blob/main/docs/concepts.md) (Unified Toolkit Ingestion)

---

## Project-Specific Concepts

| Concept ID | Name | Description |
|------------|------|-------------|
| `CONCEPT:DD-OS.governance.docdb` | Analysis Operations | MCP tool domain `analysis` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-2` | Collections Operations | MCP tool domain `collections` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-3` | Crud Operations | MCP tool domain `crud` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-4` | System Information & Health | MCP tool domain `system` — Action-routed dynamic tool registration |
| `CONCEPT:DD-OS.governance.docdb-5` | Users Operations | MCP tool domain `users` — Action-routed dynamic tool registration |

## Cross-Project References (from agent-connector-sdk)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:AU-ECO.messaging.native-backend-abstraction` | Unified Toolkit Ingestion | agent-connector-sdk |
| `CONCEPT:AU-ORCH.adapter.hot-cache-invalidation` | Confidence-Gated Router | agent-connector-sdk |
| `CONCEPT:AU-OS.config.secrets-authentication` | Prompt Injection Defense | agent-connector-sdk |
| `CONCEPT:AU-OS.state.cognitive-scheduler-preemption` | Cognitive Scheduler | agent-connector-sdk |
| `CONCEPT:AU-OS.governance.reactive-multi-axis-budget` | Guardrail Engine | agent-connector-sdk |
| `CONCEPT:AU-OS.governance.wasm-micro-agent-sandbox` | Audit Logging | agent-connector-sdk |
| `CONCEPT:AU-KG.query.object-graph-mapper` | Knowledge Graph Core | agent-connector-sdk |

## Synergy with agent-connector-sdk

This project integrates with `agent-connector-sdk` via `CONCEPT:AU-ECO.messaging.native-backend-abstraction` (Unified Toolkit Ingestion). The `documentdb_mcp` MCP server registers its tools with the agent-connector-sdk FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all DOCDB-* concepts.
