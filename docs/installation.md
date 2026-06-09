# Installation

`documentdb-mcp` is a standard Python package and a prebuilt container image. Pick the
path that matches how you want to run it.

## Requirements

- **Python 3.11 – 3.14**.
- A reachable **DocumentDB** or MongoDB-compatible endpoint — see
  [Backing Platform](platform.md) to deploy one locally.

## From PyPI (recommended)

```bash
pip install documentdb-mcp
```

### Optional extras

The base install ships the MCP server. Install the extra for what you need:

| Extra | Install | Pulls in |
|---|---|---|
| _(base)_ | `pip install documentdb-mcp` | MCP-server runtime (`agent-utilities[mcp]`, `pymongo`) |
| `agent` | `pip install "documentdb-mcp[agent]"` | Pydantic-AI agent + Logfire tracing (`agent-utilities[agent,logfire]`) |
| `all` | `pip install "documentdb-mcp[all]"` | MCP server, agent, and Logfire tracing |
| `test` | `pip install "documentdb-mcp[test]"` | `pytest`, `pytest-asyncio`, `pytest-cov`, `pytest-xdist` |

```bash
# Typical: run the MCP server and the integrated agent
pip install "documentdb-mcp[all]"
```

## From source

```bash
git clone https://github.com/Knuckles-Team/documentdb-mcp.git
cd documentdb-mcp
pip install -e ".[all]"          # editable install with every extra
```

With [`uv`](https://docs.astral.sh/uv/):

```bash
uv pip install -e ".[all]"
uv run documentdb-mcp
```

## Prebuilt Docker image

A multi-stage, slim image is published on every release (entrypoint
`documentdb-mcp`):

```bash
docker pull knucklessg1/documentdb-mcp:latest

docker run --rm -i \
  -e MONGODB_URI=mongodb://your-documentdb:27017/ \
  knucklessg1/documentdb-mcp:latest        # stdio transport (default)
```

For an HTTP server with a published port and the agent server, see
[Deployment](deployment.md).

## Verify the install

```bash
documentdb-mcp --help
python -c "import documentdb_mcp; print(documentdb_mcp.__version__)"
```

## Next steps

- **[Deployment](deployment.md)** — run it as a long-lived MCP server and agent behind Caddy + DNS.
- **[Usage](usage.md)** — call the tools, the API, and the CLI.
- **[Configuration](deployment.md#configuration-environment)** — every environment variable.
