# Documentdb Mcp
## CLI or API | MCP

![PyPI - Version](https://img.shields.io/pypi/v/documentdb-mcp)
![MCP Server](https://badge.mcpx.dev?type=server 'MCP Server')
![PyPI - Downloads](https://img.shields.io/pypi/dd/documentdb-mcp)
![GitHub Repo stars](https://img.shields.io/github/stars/Knuckles-Team/documentdb-mcp)
![GitHub forks](https://img.shields.io/github/forks/Knuckles-Team/documentdb-mcp)
![GitHub contributors](https://img.shields.io/github/contributors/Knuckles-Team/documentdb-mcp)
![PyPI - License](https://img.shields.io/pypi/l/documentdb-mcp)
![GitHub](https://img.shields.io/github/license/Knuckles-Team/documentdb-mcp)
![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/Knuckles-Team/documentdb-mcp)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Knuckles-Team/documentdb-mcp)
![GitHub closed pull requests](https://img.shields.io/github/issues-pr-closed/Knuckles-Team/documentdb-mcp)
![GitHub issues](https://img.shields.io/github/issues/Knuckles-Team/documentdb-mcp)
![GitHub top language](https://img.shields.io/github/languages/top/Knuckles-Team/documentdb-mcp)
![GitHub language count](https://img.shields.io/github/languages/count/Knuckles-Team/documentdb-mcp)
![GitHub repo size](https://img.shields.io/github/repo-size/Knuckles-Team/documentdb-mcp)
![GitHub repo file count (file type)](https://img.shields.io/github/directory-file-count/Knuckles-Team/documentdb-mcp)
![PyPI - Wheel](https://img.shields.io/pypi/wheel/documentdb-mcp)
![PyPI - Implementation](https://img.shields.io/pypi/implementation/documentdb-mcp)

*Version: 2.2.0*

> **Documentation** — Installation, deployment, usage across the API, CLI, MCP, and
> agent interfaces, and guidance for provisioning the DocumentDB backing service are
> maintained in the [official documentation](https://knuckles-team.github.io/documentdb-mcp/).

---

## Overview

---

## Key Features

- **Consolidated Action-Routed MCP Tools:** Minimizes token overhead and eliminates tool bloat in LLM contexts by grouping methods into optimized, togglable tool modules.
- **Enterprise-Grade Security:** Complete support for Eunomia policies, OIDC token delegation, and granular execution context tracking.
- **Native Telemetry & Tracing:** Out-of-the-box OpenTelemetry exports and native Langfuse tracing.

---

## CLI or API

Detailed instructions on how to use the underlying API wrappers, extended schema bindings, and developer SDK references are maintained in [docs/index.md](docs/index.md).

---

## MCP

This server use dynamic Action-Routed tools to optimize token overhead and maximize IDE compatibility.

### Available MCP Tools

_Auto-generated — do not edit (synced by the `mcp-readme-table` pre-commit hook)._

<!-- MCP-TOOLS-TABLE:START -->

#### Condensed action-routed tools (`MCP_TOOL_MODE=condensed`)

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `documentdb_analysis` | `ANALYSISTOOL` | Manage analysis operations. |
| `documentdb_collections` | `COLLECTIONSTOOL` | Manage collections operations. |
| `documentdb_crud` | `CRUDTOOL` | Manage crud operations. |
| `documentdb_ingest_catalog` | `KGTOOL` | Natively ingest the DocumentDB catalog into epistemic-graph as typed nodes. |
| `documentdb_ingest_documents` | `KGTOOL` | Natively ingest stored documents from a collection as ``:Document`` nodes. |
| `documentdb_system` | `SYSTEMTOOL` | Manage system operations. |
| `documentdb_users` | `USERSTOOL` | Manage users operations. |

#### Verbose 1:1 API-mapped tools (`MCP_TOOL_MODE=verbose` or `both`)

<details>
<summary>28 per-operation tools — one per public API method (click to expand)</summary>

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `documentdb_aggregate` | `ANALYSIS_CLIENTTOOL` | Invoke the aggregate operation. |
| `documentdb_binary_version` | `SYSTEM_CLIENTTOOL` | Invoke the binary_version operation. |
| `documentdb_count_documents` | `CRUD_CLIENTTOOL` | Invoke the count_documents operation. |
| `documentdb_create_collection` | `SYSTEM_CLIENTTOOL` | Invoke the create_collection operation. |
| `documentdb_create_database` | `SYSTEM_CLIENTTOOL` | Invoke the create_database operation. |
| `documentdb_create_user` | `USERS_CLIENTTOOL` | Invoke the create_user operation. |
| `documentdb_delete_many` | `CRUD_CLIENTTOOL` | Invoke the delete_many operation. |
| `documentdb_delete_one` | `CRUD_CLIENTTOOL` | Invoke the delete_one operation. |
| `documentdb_distinct` | `ANALYSIS_CLIENTTOOL` | Invoke the distinct operation. |
| `documentdb_drop_collection` | `SYSTEM_CLIENTTOOL` | Invoke the drop_collection operation. |
| `documentdb_drop_database` | `SYSTEM_CLIENTTOOL` | Invoke the drop_database operation. |
| `documentdb_drop_user` | `USERS_CLIENTTOOL` | Invoke the drop_user operation. |
| `documentdb_find` | `CRUD_CLIENTTOOL` | Invoke the find operation. |
| `documentdb_find_one` | `CRUD_CLIENTTOOL` | Invoke the find_one operation. |
| `documentdb_find_one_and_delete` | `CRUD_CLIENTTOOL` | Invoke the find_one_and_delete operation. |
| `documentdb_find_one_and_replace` | `CRUD_CLIENTTOOL` | Invoke the find_one_and_replace operation. |
| `documentdb_find_one_and_update` | `CRUD_CLIENTTOOL` | Invoke the find_one_and_update operation. |
| `documentdb_insert_many` | `CRUD_CLIENTTOOL` | Invoke the insert_many operation. |
| `documentdb_insert_one` | `CRUD_CLIENTTOOL` | Invoke the insert_one operation. |
| `documentdb_list_collections` | `SYSTEM_CLIENTTOOL` | Invoke the list_collections operation. |
| `documentdb_list_databases` | `SYSTEM_CLIENTTOOL` | Invoke the list_databases operation. |
| `documentdb_rename_collection` | `SYSTEM_CLIENTTOOL` | Invoke the rename_collection operation. |
| `documentdb_replace_one` | `CRUD_CLIENTTOOL` | Invoke the replace_one operation. |
| `documentdb_run_command` | `SYSTEM_CLIENTTOOL` | Invoke the run_command operation. |
| `documentdb_update_many` | `CRUD_CLIENTTOOL` | Invoke the update_many operation. |
| `documentdb_update_one` | `CRUD_CLIENTTOOL` | Invoke the update_one operation. |
| `documentdb_update_user` | `USERS_CLIENTTOOL` | Invoke the update_user operation. |
| `documentdb_users_info` | `USERS_CLIENTTOOL` | Invoke the users_info operation. |

</details>

_7 action-routed tool(s) · 28 verbose 1:1 tool(s). Each is enabled unless its `<DOMAIN>TOOL` toggle is set false; `MCP_TOOL_MODE` selects the surface (**`intent` default** — the six verb-tools, granular set loaded on demand · `condensed` action-routed · `verbose` 1:1 · `both`). Auto-generated — do not edit._
<!-- MCP-TOOLS-TABLE:END -->

Detailed tool schemas, parameter shapes, and validation constraints are preserved in [docs/usage.md](docs/usage.md).

### Dynamic Tool Selection & Visibility

This MCP server supports dynamic toolset selection and visibility filtering at runtime. This allows the operator to restrict the set of exposed tools to prevent blowing up the LLM's context window.

The operator can configure tool filtering via multiple input channels:

- **CLI Arguments:** Pass `--tools` or `--toolsets` (or their disabled counterparts `--disabled-tools` and `--disabled-toolsets`) during startup.
- **Environment Variables:** Define standard environment variables:
  - `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS`
  - `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS`
- **HTTP SSE Request Headers:** Pass custom headers during transport initialization:
  - `x-mcp-enabled-tools` / `x-mcp-disabled-tools`
  - `x-mcp-enabled-tags` / `x-mcp-disabled-tags`
- **HTTP SSE Request Query Parameters:** Append query parameters directly to the operator's transport connection URL:
  - `?tools=tool1,tool2`
  - `?tags=tag1`

When query strings or parameters are supplied, an LLM-free **Knowledge Graph resolution layer** (using `DynamicToolOrchestrator`) matches query intents against known tool tags, names, or descriptions, with safe fallback and automated 24-hour background cache refreshing.

---

### MCP Configuration Examples

<!-- MCP-CONFIG-EXAMPLES:START -->

> **Install the connector-focused `[mcp]` extra.** Examples use `documentdb-mcp[mcp]` to add
> FastMCP / FastAPI through `agent-connector-sdk`; the required Agent Connector SDK core
> still carries `epistemic-graph[full]`. The `[agent-runtime]` extra additionally
> enables model orchestration.

#### stdio Transport (local IDEs — Cursor, Claude Desktop, VS Code)

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "documentdb-mcp[mcp]",
        "documentdb-mcp"
      ],
      "env": {
        "MCP_TOOL_MODE": "intent",
        "ANALYSISTOOL": "True",
        "COLLECTIONSTOOL": "True",
        "CRUDTOOL": "True",
        "KGTOOL": "True",
        "MONGODB_HOST": "localhost",
        "MONGODB_PORT": "27017",
        "MONGODB_URI": "mongodb://localhost:27017/",
        "SYSTEMTOOL": "True",
        "USERSTOOL": "True"
      }
    }
  }
}
```

Runtime references require an alias-aware launcher such as Arbora. Other
launchers must omit those entries and inject the resolved values through their
own runtime secret boundary.

#### Streamable-HTTP Transport (networked / production)

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "documentdb-mcp[mcp]",
        "documentdb-mcp",
        "--transport",
        "streamable-http",
        "--port",
        "8000"
      ],
      "env": {
        "TRANSPORT": "streamable-http",
        "HOST": "127.0.0.1",
        "PORT": "8000",
        "MCP_TOOL_MODE": "intent",
        "ANALYSISTOOL": "True",
        "COLLECTIONSTOOL": "True",
        "CRUDTOOL": "True",
        "KGTOOL": "True",
        "MONGODB_HOST": "localhost",
        "MONGODB_PORT": "27017",
        "MONGODB_URI": "mongodb://localhost:27017/",
        "SYSTEMTOOL": "True",
        "USERSTOOL": "True"
      }
    }
  }
}
```

Alternatively, connect to a pre-deployed Streamable-HTTP instance by `url`:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "url": "http://localhost:8000/documentdb-mcp/mcp"
    }
  }
}
```

Run a reviewed container image as a least-privilege stdio child (no
listener or published port):

```bash
docker run -i --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -e TRANSPORT=stdio \
  -e MCP_TOOL_MODE=intent \
  -e ANALYSISTOOL=True \
  -e COLLECTIONSTOOL=True \
  -e CRUDTOOL=True \
  -e KGTOOL=True \
  -e MONGODB_HOST=localhost \
  -e MONGODB_PORT=27017 \
  -e MONGODB_URI=mongodb://localhost:27017/ \
  -e SYSTEMTOOL=True \
  -e USERSTOOL=True \
  registry.example.invalid/documentdb-mcp@sha256:<digest> documentdb-mcp
```

For containerized network HTTP, supply an authenticated TLS ingress (or
direct server TLS), exact `MCP_ALLOWED_HOSTS`, and an exact trusted-proxy
CIDR policy through the operator-owned deployment profile. The generator
does not emit an unauthenticated non-loopback listener.

_Auto-generated from the code-read env surface (`MCP_TOOL_MODE` + package vars) — do not edit._
<!-- MCP-CONFIG-EXAMPLES:END -->

<!-- BEGIN GENERATED: additional-deployment-options -->
### Additional Deployment Options

`documentdb-mcp` can run as a local stdio process or container, or behind a remote
network boundary. The
[Deployment guide](https://knuckles-team.github.io/documentdb-mcp/deployment/) carries
the detailed transport contract.

- **Local container** — launch a reviewed immutable image as a least-privilege
  stdio child with no listener or published port.
- **Remote URL** — connect through an operator-supplied authenticated HTTPS
  ingress. Keep its URL, outbound identity references, trust profile, and exact
  `MCP_ALLOWED_HOSTS` in `AgentConfig`.
<!-- END GENERATED: additional-deployment-options -->

## Agent

# Set credentials
export MONGODB_URI="mongodb://localhost:27017/"
export MONGODB_HOST="localhost"
export MONGODB_PORT="27017"

# Connector-focused MCP server (includes the shared graph engine)
uv pip install "documentdb-mcp[mcp]"

# Everything (development)
uv pip install "documentdb-mcp[all]"      # or: python -m pip install "documentdb-mcp[all]"
```

### Container images (`:mcp`)

One multi-stage `docker/Dockerfile` builds the MCP-only image (`--target mcp`):

| Image tag | Build target | Contents | Entrypoint |
|-----------|--------------|----------|------------|
| `example/documentdb-mcp:mcp` | `--target mcp` | `documentdb-mcp[mcp]` — **connector-focused**, includes `epistemic-graph[full]`; no model-orchestration stack | `documentdb-mcp` |

```bash
docker build --target mcp   -t example/documentdb-mcp:mcp    docker/   # connector-focused MCP server
```

agent (`immutable agent digest`) with a co-located `:mcp` sidecar.

### Knowledge-graph database (`epistemic-graph`)

Agent Connector SDK core dependency (`epistemic-graph[full]`). The `[mcp]` extra keeps
deployments can use the bundled engine. For production or shared state, run
**epistemic-graph as a dedicated database service** and configure the runtime to use it.
Deployment recipes (single-node + Raft HA), connection configuration, and architecture
diagrams are documented in the
[epistemic-graph deployment guide](https://knuckles-team.github.io/epistemic-graph/deployment/).
This graph service is distinct from the DocumentDB backing store used by the MCP tools; see
the connection variables above.

---

## Documentation

The complete documentation is published as the
[official documentation site](https://knuckles-team.github.io/documentdb-mcp/) and is
the recommended reference for installation, deployment, and day-to-day operation.

| Page | Contents |
|---|---|
| [Installation](https://knuckles-team.github.io/documentdb-mcp/installation/) | pip, source, extras, prebuilt Docker image |
| [Deployment](https://knuckles-team.github.io/documentdb-mcp/deployment/) | run the MCP server and agent, Compose, Caddy + Technitium, env config |
| [Usage](https://knuckles-team.github.io/documentdb-mcp/usage/) | the MCP tools, the `DocumentDBApi` client, the CLI |
| [Backing Platform](https://knuckles-team.github.io/documentdb-mcp/platform/) | deploy DocumentDB with Docker |
| [Overview](https://knuckles-team.github.io/documentdb-mcp/overview/) | ecosystem role, tool modules, configuration |
| [Concepts](https://knuckles-team.github.io/documentdb-mcp/concepts/) | concept registry (`CONCEPT:DOCDB-*`) |

---

## Repository Owners

<img width="100%" height="180em" src="https://github-readme-stats.vercel.app/api?username=example&show_icons=true&hide_border=true&&count_private=true&include_all_commits=true" />

![GitHub followers](https://img.shields.io/github/followers/example)
![GitHub User's stars](https://img.shields.io/github/stars/example)

---

## Contribute

Contributions are welcome! Please ensure code quality by running local checks before submitting pull requests:
- Format code using `ruff format .`
- Lint code using `ruff check .`
- Validate type-safety with `mypy .`
- Run test suites using `pytest`

<!-- BEGIN agent-connector-sdk-deployment (generated; do not edit between markers) -->

## Deploy with `agent-connector-sdk-deployment`

Provision this package with the consolidated **`agent-connector-sdk-deployment`**
workflow. It selects an installed-package, editable-source, or immutable-container
path; records only runtime secret and TLS-profile references in `AgentConfig`; and
runs doctor, registration, policy, observability, and rollback gates. Ask your agent
to **"deploy `documentdb-mcp` with agent-connector-sdk-deployment"**.

| Install mode | Command |
|------|---------|
| Installed package | `uv tool install "documentdb-mcp[mcp]"`, then run `documentdb-mcp` |
| Immutable container | deploy `registry.example.invalid/documentdb-mcp@sha256:<digest>` through the operator-selected orchestrator |

The repository embeds no deployment profile, credential value, certificate path, or
environment-specific endpoint. Supply those at runtime through `AgentConfig` and the
configured secret provider.

<!-- END agent-connector-sdk-deployment -->

<!-- GOVERNED-CAPABILITY:START -->
## Governed capability contract

This package ships a compact canonical skill surface with specialist procedures
kept as referenced workflows. The current MCP tools, skill metadata,
`connector_manifest.yml`, ontology, mappings, shapes, fixtures, migrations,
tool-schema fingerprints, and certification metadata form one versioned
capability contract. Validate them together; do not rely on stale tool names or
historical per-task skill wrappers.

Runtime endpoints, credentials, certificate trust, tenant identity, retention,
and observability policy are deployment inputs and are never packaged values.
See [Configuration, trust, and privacy](docs/configuration.md) before enabling a
network transport, connector ingestion, Arbora delegation, or trace export.
<!-- GOVERNED-CAPABILITY:END -->
