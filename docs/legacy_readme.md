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

*Version: 0.10.1*

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

Detailed instructions on how to use the underlying API wrappers, extended schema bindings, and developer SDK references are maintained in [docs/index.md](index.md).

---

## MCP

This server utilizes dynamic Action-Routed tools to optimize token overhead and maximize IDE compatibility.

### Available MCP Tools
| Tool Module | Toggle Env Var | Enabled by Default | Description & Nested Methods |
|-------------|----------------|--------------------|------------------------------|
| **System** | `SYSTEMTOOL` | `True` | Manage system operations. Action-routed methods: `binary_version`, `list_databases`, `run_command`. |
| **Collections** | `COLLECTIONSTOOL` | `True` | Manage collections operations. Action-routed methods: `list_collections`, `create_collection`, `drop_collection`, `create_database`, `drop_database`, `rename_collection`. |
| **Users** | `USERSTOOL` | `True` | Manage users operations. Action-routed methods: `create_user`, `drop_user`, `update_user`, `users_info`. |
| **Crud** | `CRUDTOOL` | `True` | Manage crud operations. Action-routed methods: `insert_one`, `insert_many`, `find_one`, `find`, `replace_one`, `update_one`, `update_many`, `delete_one`, `delete_many`, `count_documents`, `find_one_and_update`, `find_one_and_replace`, `find_one_and_delete`. |
| **Analysis** | `ANALYSISTOOL` | `True` | Manage analysis operations. Action-routed methods: `distinct`, `aggregate`. |

Detailed tool schemas, parameter shapes, and validation constraints are preserved in [docs/mcp.md](mcp.md).

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
        "DOCUMENT_DB_PASSWORD": "your_document_db_password_here",
        "DOCUMENT_DB_NAME": "your_document_db_name_here"
      }
    }
  }
}
```

#### Streamable-HTTP Transport (Recommended for production deployments)
To run the server as a long-running Streamable-HTTP service:

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
  -e DOCUMENT_DB_PASSWORD="your_value" \
  -e DOCUMENT_DB_NAME="your_value" \
  knucklessg1/documentdb-mcp:latest
```

---

## Agent

This repository features a fully integrated Pydantic AI Graph Agent. It communicates over the **Agent Control Protocol (ACP)** and interacts seamlessly with the **Agent Web UI (AG-UI)** and Terminal interface.

### Running the Agent CLI
To start the interactive command-line agent:

```bash
# Set credentials
export DOCUMENT_DB_HOST="your_value"
export DOCUMENT_DB_PORT="your_value"
export DOCUMENT_DB_USERNAME="your_value"
export DOCUMENT_DB_PASSWORD="your_value"
export DOCUMENT_DB_NAME="your_value"

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

Detailed graph node architecture explanations, custom skill configurations, and agentic trace guides are available in [docs/agent.md](agent.md).

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
