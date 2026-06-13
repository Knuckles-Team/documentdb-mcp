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

*Version: 0.40.0*

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
| Tool Module | Toggle Env Var | Enabled by Default | Description & Nested Methods |
|-------------|----------------|--------------------|------------------------------|
| **System** | `SYSTEM_TOOL` | `True` | Register system tools.

    CONCEPT:ECO-4.1 Action-routed methods: `binary_version`, `list_databases`, `run_command`. |
| **Collections** | `COLLECTIONS_TOOL` | `True` | Register collections tools.

    CONCEPT:ECO-4.1 Action-routed methods: `create_collection`, `create_database`, `drop_collection`, `drop_database`, `list_collections`, `rename_collection`. |
| **Users** | `USERS_TOOL` | `True` | Register users tools.

    CONCEPT:ECO-4.1 Action-routed methods: `create_user`, `drop_user`, `update_user`, `users_info`. |
| **Crud** | `CRUD_TOOL` | `True` | Register crud tools.

    CONCEPT:ECO-4.1 Action-routed methods: `count_documents`, `delete_many`, `delete_one`, `find`, `find_one`, `find_one_and_delete`, `find_one_and_replace`, `find_one_and_update`, `insert_many`, `insert_one`, `replace_one`, `update_many`, `update_one`. |
| **Analysis** | `ANALYSIS_TOOL` | `True` | Register analysis tools.

    CONCEPT:ECO-4.1 Action-routed methods: `aggregate`, `distinct`. |

        Actions:
          - 'binary_version': Call binary_version
          - 'list_databases': Call list_databases
          - 'run_command': Call run_command Action-routed methods: `binary_version`, `list_databases`, `run_command`. |
| **Collections** | `COLLECTIONS_TOOL` | `True` | Manage collections operations.

        Actions:
          - 'list_collections': Call list_collections
          - 'create_collection': Call create_collection
          - 'drop_collection': Call drop_collection
          - 'create_database': Call create_database
          - 'drop_database': Call drop_database
          - 'rename_collection': Call rename_collection Action-routed methods: `create_collection`, `create_database`, `drop_collection`, `drop_database`, `list_collections`, `rename_collection`. |
| **Users** | `USERS_TOOL` | `True` | Manage users operations.

        Actions:
          - 'create_user': Call create_user
          - 'drop_user': Call drop_user
          - 'update_user': Call update_user
          - 'users_info': Call users_info Action-routed methods: `create_user`, `drop_user`, `update_user`, `users_info`. |
| **Crud** | `CRUD_TOOL` | `True` | Manage crud operations.

        Actions:
          - 'insert_one': Call insert_one
          - 'insert_many': Call insert_many
          - 'find_one': Call find_one
          - 'find': Call find
          - 'replace_one': Call replace_one
          - 'update_one': Call update_one
          - 'update_many': Call update_many
          - 'delete_one': Call delete_one
          - 'delete_many': Call delete_many
          - 'count_documents': Call count_documents
          - 'find_one_and_update': Call find_one_and_update
          - 'find_one_and_replace': Call find_one_and_replace
          - 'find_one_and_delete': Call find_one_and_delete Action-routed methods: `count_documents`, `delete_many`, `delete_one`, `find`, `find_one`, `find_one_and_delete`, `find_one_and_replace`, `find_one_and_update`, `insert_many`, `insert_one`, `replace_one`, `update_many`, `update_one`. |
| **Analysis** | `ANALYSIS_TOOL` | `True` | Manage analysis operations.

        Actions:
          - 'distinct': Call distinct
          - 'aggregate': Call aggregate Action-routed methods: `aggregate`, `distinct`. |

        Actions:
          - 'binary_version': Call binary_version
          - 'list_databases': Call list_databases
          - 'run_command': Call run_command Action-routed methods: `binary_version`, `list_databases`, `run_command`. |
| **Collections** | `COLLECTIONS_TOOL` | `True` | Manage collections operations.

        Actions:
          - 'list_collections': Call list_collections
          - 'create_collection': Call create_collection
          - 'drop_collection': Call drop_collection
          - 'create_database': Call create_database
          - 'drop_database': Call drop_database
          - 'rename_collection': Call rename_collection Action-routed methods: `create_collection`, `create_database`, `drop_collection`, `drop_database`, `list_collections`, `rename_collection`. |
| **Users** | `USERS_TOOL` | `True` | Manage users operations.

        Actions:
          - 'create_user': Call create_user
          - 'drop_user': Call drop_user
          - 'update_user': Call update_user
          - 'users_info': Call users_info Action-routed methods: `create_user`, `drop_user`, `update_user`, `users_info`. |
| **Crud** | `CRUD_TOOL` | `True` | Manage crud operations.

        Actions:
          - 'insert_one': Call insert_one
          - 'insert_many': Call insert_many
          - 'find_one': Call find_one
          - 'find': Call find
          - 'replace_one': Call replace_one
          - 'update_one': Call update_one
          - 'update_many': Call update_many
          - 'delete_one': Call delete_one
          - 'delete_many': Call delete_many
          - 'count_documents': Call count_documents
          - 'find_one_and_update': Call find_one_and_update
          - 'find_one_and_replace': Call find_one_and_replace
          - 'find_one_and_delete': Call find_one_and_delete Action-routed methods: `count_documents`, `delete_many`, `delete_one`, `find`, `find_one`, `find_one_and_delete`, `find_one_and_replace`, `find_one_and_update`, `insert_many`, `insert_one`, `replace_one`, `update_many`, `update_one`. |
| **Analysis** | `ANALYSIS_TOOL` | `True` | Manage analysis operations.

        Actions:
          - 'distinct': Call distinct
          - 'aggregate': Call aggregate Action-routed methods: `aggregate`, `distinct`. |

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

#### stdio Transport (Recommended for local IDEs e.g., Cursor, Claude Desktop)
Configure your IDE's `mcp.json` to launch the MCP server via `uvx`:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "documentdb-mcp",
        "documentdb-mcp"
      ],
      "env": {
        "DOCUMENT_DB_HOST": "your_document_db_host_here",
        "DOCUMENT_DB_PORT": "your_document_db_port_here",
        "DOCUMENT_DB_USERNAME": "your_document_db_username_here",
        "DOCUMENT_DB_NAME": "your_document_db_name_here",
        "DOCUMENT_DB_PASSWORD": "your_document_db_password_here"
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
        "documentdb-mcp",
        "documentdb-mcp"
      ],
      "env": {
        "TRANSPORT": "streamable-http",
        "HOST": "0.0.0.0",
        "PORT": "8000",
        "DOCUMENT_DB_HOST": "your_document_db_host_here",
        "DOCUMENT_DB_PORT": "your_document_db_port_here",
        "DOCUMENT_DB_USERNAME": "your_document_db_username_here",
        "DOCUMENT_DB_NAME": "your_document_db_name_here",
        "DOCUMENT_DB_PASSWORD": "your_document_db_password_here"
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
  -e DOCUMENT_DB_HOST="your_value" \
  -e DOCUMENT_DB_PORT="your_value" \
  -e DOCUMENT_DB_USERNAME="your_value" \
  -e DOCUMENT_DB_NAME="your_value" \
  -e DOCUMENT_DB_PASSWORD="your_value" \
  knucklessg1/documentdb-mcp:latest
```

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
export DOCUMENT_DB_HOST="your_value"
export DOCUMENT_DB_PORT="your_value"
export DOCUMENT_DB_USERNAME="your_value"
export DOCUMENT_DB_NAME="your_value"
export DOCUMENT_DB_PASSWORD="your_value"

# Run the agent server
documentdb-agent --provider openai --model-id gpt-4o
```

### Docker Compose Orchestration
The following `docker/agent.compose.yml` configures the Agent, Web UI, and Terminal Interface together:

```yaml
version: '3.8'

services:
  documentdb-mcp-mcp:
    image: knucklessg1/documentdb-mcp:latest
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

The server and agent can be configured using the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGODB_URI` | The connection URI for the MongoDB/DocumentDB server. | `mongodb://localhost:27017/` |
| `MONGODB_HOST` | The MongoDB/DocumentDB server host. | `localhost` |
| `MONGODB_PORT` | The MongoDB/DocumentDB server port. | `27017` |
| `AUTH_TYPE` | The authentication mechanism to use (scram-sha-256, scram-sha-1, none). | `scram-sha-256` |
| `SYSTEMTOOL` | Toggle switch to enable or disable the System tool module. | `True` |
| `COLLECTIONSTOOL` | Toggle switch to enable or disable the Collections tool module. | `True` |
| `USERSTOOL` | Toggle switch to enable or disable the Users tool module. | `True` |
| `CRUDTOOL` | Toggle switch to enable or disable the CRUD tool module. | `True` |
| `ANALYSISTOOL` | Toggle switch to enable or disable the Analysis tool module. | `True` |
| `EUNOMIA_TYPE` | Enterprise policy type (none, embedded, remote). | `none` |
| `EUNOMIA_POLICY_FILE` | Path to Eunomia security policy configuration file. | `mcp_policies.json` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry OTLP receiver endpoint. | `None` |

---

## Installation

Install the Python package locally:

```bash
# Using uv (highly recommended)
uv pip install documentdb-mcp[all]

# Using standard pip
python -m pip install documentdb-mcp[all]
```

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
