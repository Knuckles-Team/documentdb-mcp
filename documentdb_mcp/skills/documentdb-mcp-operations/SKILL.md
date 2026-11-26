---
name: documentdb-mcp-operations
skill_type: skill
description: >-
  Operate documentdb-mcp through its governed MCP and Arbora capabilities, including documentdb aggregation analytics, documentdb collection admin, documentdb document crud, documentdb starter. Use when a request requires this provider's read, change, automation, ingestion, troubleshooting, or evidence workflows.
---

# Documentdb Mcp Operations

Use the provider's governed MCP tools through Arbora delegation.

## Steps

1. Establish the verified session and tenant, and list the tool surface with the `find` operation of the Arbora MCP server.
   Verify the documentdb tools are listed before choosing one.
2. Open the workflow catalog at `references/catalog.md` only if the request needs a provider-specific procedure.
   Verify the procedure matches the tool names just discovered.
3. Run a read-only tool first, for example `documentdb_list_databases`.
   Verify it returns data without an authorization error.
4. For any change, present the impact to the operator and preview it by calling the Arbora tool without `execute=true`.
   Verify the preview names the exact database and collection affected.
5. Execute the approved change and read it back with `documentdb_find`.
   Verify the observed state matches the stated impact.

## Failure recovery

| Failure | Cause | Recovery |
|---------|-------|----------|
| Tool not found | Stale tool name or schema | Re-run discovery with `find` and use the exact name returned |
| Connection error or server-selection timeout | `MONGODB_URI`, or `MONGODB_HOST` and `MONGODB_PORT`, unset or unreachable | Set `MONGODB_URI` for the `documentdb-mcp` server and call `documentdb_list_databases` to confirm; ask the operator for the correct endpoint |
| Execution refused | Unknown ACL or tenant state, or approval missing | Treat it as a hard failure, report it, and ask the operator to fix the session before calling `documentdb_list_databases` again |

## Workflow

1. Establish the verified GraphSession and tenant before discovery or retrieval.
2. Discover the current tool surface; never assume a stale tool name or schema.
3. Prefer read-only inspection first. For changes, present impact and use the provider's
   dry-run or preview mode when available.
4. Execute mutations as fenced WorkItems so retries remain idempotent and auditable.
5. Ingest source data only through the signed connector preset and ChangeEnvelope path.
6. Verify the durable result and its trace/evidence before reporting completion.

## Safety contract

- Never persist credentials, endpoints, raw personal identifiers, hostnames, or local paths.
- Resolve TLS trust and verification from environment/configuration; never hardcode bypasses.
- Treat unknown ACL, tenant, schema, or tool-contract state as a hard failure.
- Require explicit approval for destructive, externally visible, or irreversible actions.
- Keep runtime traces policy-scoped and privacy-sanitized.

## Specialized workflows

Read [the workflow catalog](references/catalog.md) only when the request needs a
provider-specific procedure, parameter map, script, or reference asset.
