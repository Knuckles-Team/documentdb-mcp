# Concept Registry — documentdb-mcp

> **Prefix**: `CONCEPT:DOCDB-*`
> **Version**: 0.13.0
> **Bridge**: [`CONCEPT:ECO-4.0`](https://github.com/Knuckles-Team/agent-utilities/blob/main/docs/concepts.md) (Unified Toolkit Ingestion)

---

## Project-Specific Concepts

| Concept ID | Name | Description |
|------------|------|-------------|
| `CONCEPT:DOCDB-001` | Analysis Operations | MCP tool domain `analysis` — Action-routed dynamic tool registration |
| `CONCEPT:DOCDB-002` | Collections Operations | MCP tool domain `collections` — Action-routed dynamic tool registration |
| `CONCEPT:DOCDB-003` | Crud Operations | MCP tool domain `crud` — Action-routed dynamic tool registration |
| `CONCEPT:DOCDB-004` | System Information & Health | MCP tool domain `system` — Action-routed dynamic tool registration |
| `CONCEPT:DOCDB-005` | Users Operations | MCP tool domain `users` — Action-routed dynamic tool registration |

## Cross-Project References (from agent-utilities)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:ECO-4.0` | Unified Toolkit Ingestion | agent-utilities |
| `CONCEPT:ORCH-1.2` | Confidence-Gated Router | agent-utilities |
| `CONCEPT:OS-5.1` | Prompt Injection Defense | agent-utilities |
| `CONCEPT:OS-5.2` | Cognitive Scheduler | agent-utilities |
| `CONCEPT:OS-5.3` | Guardrail Engine | agent-utilities |
| `CONCEPT:OS-5.4` | Audit Logging | agent-utilities |
| `CONCEPT:KG-2.0` | Knowledge Graph Core | agent-utilities |

## Synergy with agent-utilities

This project integrates with `agent-utilities` via `CONCEPT:ECO-4.0` (Unified Toolkit Ingestion). The `documentdb_mcp` MCP server registers its tools with the agent-utilities FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all DOCDB-* concepts.
