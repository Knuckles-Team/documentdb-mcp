# Documentdb Mcp
## CLI or API | MCP | Agent

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

*Version: 1.0.0*

> **Documentation** — Installation, deployment, usage across the API, CLI, MCP, and
> agent interfaces, and guidance for provisioning the DocumentDB backing service are
> maintained in the [official documentation](https://knuckles-team.github.io/documentdb-mcp/).

---

## Overview

**Documentdb Mcp** is a production-grade Agent and Model Context Protocol (MCP) server designed to interface directly with DocumentDB MCP Server & A2A Server. DocumentDB is a MongoDB compatible open source document database built on PostgreSQL..

---

## Key Features

- **Consolidated Action-Routed MCP Tools:** Minimizes token overhead and eliminates tool bloat in LLM contexts by grouping methods into optimized, togglable tool modules.
- **Enterprise-Grade Security:** Comprehensive support for Eunomia policies, OIDC token delegation, and granular execution context tracking.
- **Integrated Graph Agent:** Built-in Pydantic AI agent supporting the Agent Control Protocol (ACP) and standard Web interfaces (AG-UI).
- **Native Telemetry & Tracing:** Out-of-the-box OpenTelemetry exports and native Langfuse tracing.

---

## CLI or API

This agent wraps the DocumentDB MCP Server & A2A Server. DocumentDB is a MongoDB compatible open source document database built on PostgreSQL. API. You can interact with it programmatically or via its integrated execution entrypoints.

Detailed instructions on how to use the underlying API wrappers, extended schema bindings, and developer SDK references are maintained in [docs/index.md](docs/index.md).

---

## MCP

This server utilizes dynamic Action-Routed tools to optimize token overhead and maximize IDE compatibility.

### Available MCP Tools

_Auto-generated — do not edit (synced by the `mcp-readme-table` pre-commit hook)._

<!-- MCP-TOOLS-TABLE:START -->

#### Condensed action-routed tools (default — `MCP_TOOL_MODE=condensed`)

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `documentdb_analysis` | `ANALYSISTOOL` | Manage analysis operations. |
| `documentdb_collections` | `COLLECTIONSTOOL` | Manage collections operations. |
| `documentdb_crud` | `CRUDTOOL` | Manage crud operations. |
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

_5 action-routed tool(s) (default) · 28 verbose 1:1 tool(s). Each is enabled unless its `<DOMAIN>TOOL` toggle is set false; `MCP_TOOL_MODE` selects the surface (`condensed` default · `verbose` 1:1 · `both`). Auto-generated — do not edit._
<!-- MCP-TOOLS-TABLE:END -->

Detailed tool schemas, parameter shapes, and validation constraints are preserved in [docs/mcp.md](docs/mcp.md).

### Dynamic Tool Selection & Visibility

This MCP server supports dynamic toolset selection and visibility filtering at runtime. This allows you to restrict the set of exposed tools in order to prevent blowing up the LLM's context window.

You can configure tool filtering via multiple input channels:

- **CLI Arguments:** Pass `--tools` or `--toolsets` (or their disabled counterparts `--disabled-tools` and `--disabled-toolsets`) during startup.
- **Environment Variables:** Define standard environment variables:
  - `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS`
  - `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS`
- **HTTP SSE Request Headers:** Pass custom headers during transport initialization:
  - `x-mcp-enabled-tools` / `x-mcp-disabled-tools`
  - `x-mcp-enabled-tags` / `x-mcp-disabled-tags`
- **HTTP SSE Request Query Parameters:** Append query parameters directly to your transport connection URL:
  - `?tools=tool1,tool2`
  - `?tags=tag1`

When query strings or parameters are supplied, an LLM-free **Knowledge Graph resolution layer** (using `DynamicToolOrchestrator`) matches query intents against known tool tags, names, or descriptions, with safe fallback and automated 24-hour background cache refreshing.

---

### MCP Configuration Examples

> **Install the slim `[mcp]` extra.** All examples below install
> `documentdb-mcp[mcp]` — the MCP-server extra that pulls only the FastMCP /
> FastAPI tooling (`agent-utilities[mcp]`). It deliberately **excludes** the heavy
> agent runtime (the epistemic-graph engine, `pydantic-ai`, `dspy`, `llama-index`,
> `tree-sitter`), so `uvx`/container installs are dramatically smaller and faster.
> Use the full `[agent]` extra only when you need the integrated Pydantic AI agent
> (see [Installation](#installation)).

#### stdio Transport (Recommended for local IDEs e.g., Cursor, Claude Desktop)
Configure your IDE's `mcp.json` to launch the MCP server via `uvx`:

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
        "MONGODB_URI": "mongodb://localhost:27017/",
        "MONGODB_HOST": "localhost",
        "MONGODB_PORT": "27017"
      }
    }
  }
}
```

#### Streamable-HTTP Transport (Recommended for production deployments)
Configure your client's `mcp.json` to launch the Streamable-HTTP server via `uvx` with explicit host and port definition:

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
        "TRANSPORT": "streamable-http",
        "HOST": "0.0.0.0",
        "PORT": "8000",
        "MONGODB_URI": "mongodb://localhost:27017/",
        "MONGODB_HOST": "localhost",
        "MONGODB_PORT": "27017"
      }
    }
  }
}
```

Alternatively, connect to a pre-deployed remote or local Streamable-HTTP instance:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "url": "http://localhost:8000/documentdb-mcp/mcp"
    }
  }
}
```

Deploying the Streamable-HTTP server via Docker:

```bash
docker run -d \
  --name documentdb-mcp-mcp \
  -p 8000:8000 \
  -e TRANSPORT=streamable-http \
  -e PORT=8000 \
  -e MONGODB_URI="mongodb://localhost:27017/" \
  -e MONGODB_HOST="localhost" \
  -e MONGODB_PORT="27017" \
  knucklessg1/documentdb-mcp:mcp
```

> The `:mcp` tag is the **slim MCP-server image** (built from
> `docker/Dockerfile --target mcp`, installing `documentdb-mcp[mcp]`). The default
> `:latest` tag is the **full agent image** (`--target agent`, `documentdb-mcp[agent]`)
> which also bundles the Pydantic AI agent and the epistemic-graph engine — use it
> when you run `documentdb-agent` (the agent), not just the MCP server. See
> [Container images](#container-images-mcp-vs-agent).

---

<!-- BEGIN GENERATED: additional-deployment-options -->
### Additional Deployment Options

`documentdb-mcp` can also run as a **local container** (Docker / Podman / `uv`) or be
consumed from a **remote deployment**. The
[Deployment guide](https://knuckles-team.github.io/documentdb-mcp/deployment/) has full, copy-paste
`mcp_config.json` for all four transports — **stdio**, **streamable-http**,
**local container / uv**, and **remote URL**:

- **Local container / uv** — launch the server from `mcp_config.json` via `uvx`,
  `docker run`, or `podman run`, or point at a local streamable-http container by `url`.
- **Remote URL** — connect to a server deployed behind Caddy at
  `http://documentdb-mcp.arpa/mcp` using the `"url"` key.
<!-- END GENERATED: additional-deployment-options -->

## Agent

This repository features a fully integrated Pydantic AI Graph Agent. It communicates over the **Agent Control Protocol (ACP)** and interacts seamlessly with the **Agent Web UI (AG-UI)** and Terminal interface.

### Running the Agent CLI
To start the interactive command-line agent:

```bash
# Set credentials
export MONGODB_URI="mongodb://localhost:27017/"
export MONGODB_HOST="localhost"
export MONGODB_PORT="27017"

# Run the agent server
documentdb-agent --provider openai --model-id gpt-4o
```

### Docker Compose Orchestration
The following `docker/agent.compose.yml` configures the Agent, Web UI, and Terminal Interface together:

```yaml
version: '3.8'

services:
  documentdb-mcp-mcp:
    image: knucklessg1/documentdb-mcp:mcp
    container_name: documentdb-mcp-mcp
    hostname: documentdb-mcp-mcp
    restart: always
    env_file:
      - ../.env
    environment:
      - PYTHONUNBUFFERED=1
      - HOST=0.0.0.0
      - PORT=8000
      - TRANSPORT=streamable-http
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  documentdb-mcp-agent:
    image: knucklessg1/documentdb-mcp:latest
    container_name: documentdb-mcp-agent
    hostname: documentdb-mcp-agent
    restart: always
    depends_on:
      - documentdb-mcp-mcp
    env_file:
      - ../.env
    command: [ "documentdb-agent" ]
    environment:
      - PYTHONUNBUFFERED=1
      - HOST=0.0.0.0
      - PORT=9015
      - MCP_URL=http://documentdb-mcp-mcp:8000/mcp
      - PROVIDER=${PROVIDER:-openai}
      - MODEL_ID=${MODEL_ID:-gpt-4o}
      - ENABLE_WEB_UI=True
      - ENABLE_OTEL=True
    ports:
      - "9015:9015"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9015/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

```

Detailed graph node architecture explanations, custom skill configurations, and agentic trace guides are available in [docs/agent.md](docs/agent.md).

---

## Security & Governance

Built directly upon the enterprise-ready [`agent-utilities`](https://github.com/Knuckles-Team/agent-utilities) core, standard security parameters are fully supported:

### Access Control & Policy Enforcement
- **Eunomia Policies:** Fine-grained, policy-driven tool authorization. Supports `none`, local `embedded` (`mcp_policies.json`), or centralized `remote` modes.
- **OIDC Token Delegation:** Compliant with RFC 8693 token exchange for flowing authenticating user credentials from Web UI / ACP → Agent → MCP.
- **Scoped Credentials:** Execution context runs restricted to the specific caller identity.

### Runtime Security Grid
| Feature | Functionality | Enablement |
|---------|---------------|------------|
| **Tool Guard** | Sensitivity inspection with human-in-the-loop validation | Enabled by default |
| **Prompt Injection Defense** | Input scanning, repetition monitoring, and recursive loop blocks | Enabled by default |
| **Context Safety Guard** | Stuck-loop detectors and contextual overflow preemptive alerts | Enabled by default |

## Environment Variables

<!-- ENV-VARS-TABLE:START -->

#### Package environment variables

| Variable | Example | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` |  |
| `PORT` | `8000` |  |
| `TRANSPORT` | `stdio` | options: stdio, streamable-http, sse |
| `ENABLE_OTEL` | `True` |  |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:8080/api/public/otel` |  |
| `OTEL_EXPORTER_OTLP_PUBLIC_KEY` | `pk-...` |  |
| `OTEL_EXPORTER_OTLP_SECRET_KEY` | `sk-...` |  |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |  |
| `EUNOMIA_TYPE` | `none` | options: none, embedded, remote |
| `EUNOMIA_POLICY_FILE` | `mcp_policies.json` |  |
| `EUNOMIA_REMOTE_URL` | `http://eunomia-server:8000` |  |
| `AUTH_TYPE` | `scram-sha-256` | options: scram-sha-1, scram-sha-256, standard, none |
| `MONGODB_URI` | `mongodb://localhost:27017/` |  |
| `MONGODB_HOST` | `localhost` |  |
| `MONGODB_PORT` | `27017` |  |
| `SYSTEMTOOL` | `True` |  |
| `COLLECTIONSTOOL` | `True` |  |
| `USERSTOOL` | `True` |  |
| `CRUDTOOL` | `True` |  |
| `ANALYSISTOOL` | `True` |  |

#### Inherited agent-utilities variables (apply to every connector)

| Variable | Example | Description |
|----------|---------|-------------|
| `MCP_TOOL_MODE` | `condensed` | Tool surface: `condensed` | `verbose` | `both` |
| `MCP_ENABLED_TOOLS` | — | Comma-separated tool allow-list |
| `MCP_DISABLED_TOOLS` | — | Comma-separated tool deny-list |
| `MCP_ENABLED_TAGS` | — | Comma-separated tag allow-list |
| `MCP_DISABLED_TAGS` | — | Comma-separated tag deny-list |
| `MCP_CLIENT_AUTH` | — | Outbound MCP auth (`oidc-client-credentials` for fleet calls) |
| `OIDC_CLIENT_ID` | — | OIDC client id (service-account auth) |
| `OIDC_CLIENT_SECRET` | — | OIDC client secret (service-account auth) |
| `DEBUG` | `False` | Verbose logging |
| `PYTHONUNBUFFERED` | `1` | Unbuffered stdout (recommended in containers) |
| `MCP_URL` | `http://localhost:8000/mcp` | URL of the MCP server the agent connects to |
| `PROVIDER` | `openai` | LLM provider for the agent |
| `MODEL_ID` | `gpt-4o` | Model id for the agent |
| `ENABLE_WEB_UI` | `True` | Serve the AG-UI web interface |

_20 package + 14 inherited variable(s). Auto-generated from `.env.example` + the shared agent-utilities set — do not edit._
<!-- ENV-VARS-TABLE:END -->


Every variable the server reads, grouped by purpose.

### MCP server / transport
| Variable | Description | Default |
|----------|-------------|---------|
| `TRANSPORT` | `stdio`, `streamable-http`, or `sse` | `stdio` |
| `HOST` | Bind host (HTTP transports) | `0.0.0.0` |
| `PORT` | Bind port (HTTP transports) | `8000` |
| `MCP_TOOL_MODE` | Tool surface: `condensed`, `verbose`, or `both` | `condensed` |
| `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS` | Comma-separated tool allow/deny list | — |
| `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS` | Comma-separated tag allow/deny list | — |
| `DEBUG` | Verbose logging | `False` |
| `PYTHONUNBUFFERED` | Unbuffered stdout (recommended in containers) | `1` |

### Connection & Credentials
| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_TYPE` | Auth mechanism: `scram-sha-256`, `scram-sha-1`, `standard`, `none` | `scram-sha-256` |
| `MONGODB_URI` | MongoDB-compatible driver connection URI | `mongodb://localhost:27017/` |
| `MONGODB_HOST` | MongoDB-compatible driver host | `localhost` |
| `MONGODB_PORT` | MongoDB-compatible driver port | `27017` |

### Tool toggles
Each action-routed tool can be disabled individually via its toggle env var (set to `false`).
The full list is in the [Available MCP Tools](#available-mcp-tools) table above.
| Variable | Tool |
|----------|------|
| `SYSTEMTOOL` | `documentdb_system` |
| `COLLECTIONSTOOL` | `documentdb_collections` |
| `USERSTOOL` | `documentdb_users` |
| `CRUDTOOL` | `documentdb_crud` |
| `ANALYSISTOOL` | `documentdb_analysis` |

### Telemetry & governance
| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_OTEL` | Enable OpenTelemetry export | `True` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | — |
| `OTEL_EXPORTER_OTLP_PUBLIC_KEY` / `OTEL_EXPORTER_OTLP_SECRET_KEY` | OTLP auth keys | — |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | OTLP protocol (e.g. `http/protobuf`) | — |
| `EUNOMIA_TYPE` | Authorization mode: `none`, `embedded`, `remote` | `none` |
| `EUNOMIA_POLICY_FILE` | Embedded policy file | `mcp_policies.json` |
| `EUNOMIA_REMOTE_URL` | Remote Eunomia server URL | — |

### Agent CLI (full `[agent]` runtime only)
| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_URL` | URL of the MCP server the agent connects to | `http://localhost:8000/mcp` |
| `PROVIDER` | LLM provider (e.g. `openai`) | `openai` |
| `MODEL_ID` | Model id (e.g. `gpt-4o`) | `gpt-4o` |
| `ENABLE_WEB_UI` | Serve the AG-UI web interface | `True` |

See [`.env.example`](.env.example) for a copy-paste starting point.

---

## Installation

Pick the extra that matches what you want to run:

| Extra | Installs | Use when |
|-------|----------|----------|
| `documentdb-mcp[mcp]` | Slim MCP server only (`agent-utilities[mcp]` — FastMCP/FastAPI) | You only run the **MCP server** (smallest install / image) |
| `documentdb-mcp[agent]` | Full agent runtime (`agent-utilities[agent,logfire]` — Pydantic AI + the epistemic-graph engine) | You run the **integrated agent** |
| `documentdb-mcp[all]` | Everything (`mcp` + `agent` + `logfire`) | Development / both surfaces |

```bash
# MCP server only (recommended for tool hosting — slim deps)
uv pip install "documentdb-mcp[mcp]"

# Full agent runtime (Pydantic AI + epistemic-graph engine)
uv pip install "documentdb-mcp[agent]"

# Everything (development)
uv pip install "documentdb-mcp[all]"      # or: python -m pip install "documentdb-mcp[all]"
```

### Container images (`:mcp` vs `:agent`)

One multi-stage `docker/Dockerfile` builds two right-sized images, selected by `--target`:

| Image tag | Build target | Contents | Entrypoint |
|-----------|--------------|----------|------------|
| `knucklessg1/documentdb-mcp:mcp` | `--target mcp` | `documentdb-mcp[mcp]` — **slim**, no engine/`pydantic-ai`/`dspy`/`llama-index`/`tree-sitter` | `documentdb-mcp` |
| `knucklessg1/documentdb-mcp:latest` | `--target agent` (default) | `documentdb-mcp[agent]` — **full** agent runtime + epistemic-graph engine | `documentdb-agent` |

```bash
docker build --target mcp   -t knucklessg1/documentdb-mcp:mcp    docker/   # slim MCP server
docker build --target agent -t knucklessg1/documentdb-mcp:latest docker/   # full agent
```

`docker/mcp.compose.yml` runs the slim `:mcp` server; `docker/agent.compose.yml` runs the
agent (`:latest`) with a co-located `:mcp` sidecar.

### Knowledge-graph database (`epistemic-graph`)

The **full agent** (`[agent]` / `:latest`) embeds the **epistemic-graph** engine (pulled in
transitively via `agent-utilities[agent]`). For production — or to share one knowledge graph
across multiple agents — run **epistemic-graph as its own database container** and point the
agent at it instead of embedding it. Deployment recipes (single-node + Raft HA), connection
config, and the full database architecture (with diagrams) are documented in the
[epistemic-graph deployment guide](https://knuckles-team.github.io/epistemic-graph/deployment/).
The slim `[mcp]` server does **not** require the database. (This is distinct from the
DocumentDB backing store the MCP tools operate on — see the connection variables above.)

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

<img width="100%" height="180em" src="https://github-readme-stats.vercel.app/api?username=Knucklessg1&show_icons=true&hide_border=true&&count_private=true&include_all_commits=true" />

![GitHub followers](https://img.shields.io/github/followers/Knucklessg1)
![GitHub User's stars](https://img.shields.io/github/stars/Knucklessg1)

---

## Contribute

Contributions are welcome! Please ensure code quality by executing local checks before submitting pull requests:
- Format code using `ruff format .`
- Lint code using `ruff check .`
- Validate type-safety with `mypy .`
- Execute test suites using `pytest`


<!-- BEGIN agent-os-genesis-deploy (generated; do not edit between markers) -->

## Deploy with `agent-os-genesis`

This package can be provisioned for you — skill-guided — by the **`agent-os-genesis`**
universal skill (its *single-package deploy mode*): it picks your install method, seeds
secrets to OpenBao/Vault (or `.env`), trusts your enterprise CA, registers the MCP
server, and verifies it — the same machinery that stands up the whole Agent OS, narrowed
to just this package. Ask your agent to **"deploy `documentdb-mcp` with agent-os-genesis"**.

| Install mode | Command |
|------|---------|
| Bare-metal, prod (PyPI) | `uvx documentdb-mcp` · or `uv tool install documentdb-mcp` |
| Bare-metal, dev (editable) | `uv pip install -e ".[all]"` · or `pip install -e ".[all]"` |
| Container, prod | deploy `knucklessg1/documentdb-mcp:latest` via docker-compose / swarm / podman / podman-compose / kubernetes |
| Container, dev (editable) | deploy `docker/compose.dev.yml` (source-mounted at `/src`; edits live on restart) |

Secrets are read-existing + seeded via `vault_sync` — you are only prompted for what's missing.

<!-- END agent-os-genesis-deploy -->
