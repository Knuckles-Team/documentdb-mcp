# Deployment

<!-- BEGIN GENERATED: deployment-options -->
## Deployment Options

`documentdb-mcp` exposes its MCP server (console script `documentdb-mcp`) four ways. Pick the row that
matches where the server runs relative to your MCP client, then copy the matching
`mcp_config.json` below. Replace the `<your-…>` placeholders with the values from the **Configuration / Environment Variables** section.

| # | Option | Transport | Where it runs | `mcp_config.json` key |
|---|--------|-----------|---------------|------------------------|
| 1 | stdio | `stdio` | client launches a subprocess | `command` |
| 2 | Streamable-HTTP (local) | `streamable-http` | a local network port | `command` or `url` |
| 3 | Local container / uv | `stdio` or `streamable-http` | Docker / Podman / uv on this host | `command` or `url` |
| 4 | Remote URL | `streamable-http` | a remote host behind Caddy | `url` |

### 1. stdio (local subprocess)

The client launches the server over stdio via `uvx` — best for local IDEs
(Cursor, Claude Desktop, VS Code):

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uvx",
      "args": ["--from", "documentdb-mcp", "documentdb-mcp"],
      "env": {
        "DOCUMENT_DB_HOST": "<your-document_db_host>",
        "MONGODB_HOST": "<your-mongodb_host>",
        "DOCUMENT_DB_USERNAME": "<your-document_db_username>"
      }
    }
  }
}
```

### 2. Streamable-HTTP (local process)

Run the server as a long-lived HTTP process:

```bash
uvx --from documentdb-mcp documentdb-mcp --transport streamable-http --host 0.0.0.0 --port 8000
curl -s http://localhost:8000/health        # {"status":"OK"}
```

Then either let the client launch it:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uvx",
      "args": ["--from", "documentdb-mcp", "documentdb-mcp", "--transport", "streamable-http", "--port", "8000"],
      "env": {
        "TRANSPORT": "streamable-http",
        "HOST": "0.0.0.0",
        "PORT": "8000",
        "DOCUMENT_DB_HOST": "<your-document_db_host>",
        "MONGODB_HOST": "<your-mongodb_host>",
        "DOCUMENT_DB_USERNAME": "<your-document_db_username>"
      }
    }
  }
}
```

…or connect to the already-running process by URL:

```json
{
  "mcpServers": {
    "documentdb-mcp": { "url": "http://localhost:8000/mcp" }
  }
}
```

### 3. Local container / uv

**(a) Launch a container directly from `mcp_config.json`** (stdio over the container —
no ports to manage). Swap `docker` for `podman` for a daemonless runtime:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "TRANSPORT=stdio",
        "-e", "DOCUMENT_DB_HOST=<your-document_db_host>",
        "-e", "MONGODB_HOST=<your-mongodb_host>",
        "-e", "DOCUMENT_DB_USERNAME=<your-document_db_username>",
        "knucklessg1/documentdb-mcp:latest"
      ]
    }
  }
}
```

**(b) Run a local streamable-http container, then connect by URL:**

```bash
docker run -d --name documentdb-mcp -p 8000:8000 \
  -e TRANSPORT=streamable-http \
  -e PORT=8000 \
  -e DOCUMENT_DB_HOST="<your-document_db_host>" \
  -e MONGODB_HOST="<your-mongodb_host>" \
  -e DOCUMENT_DB_USERNAME="<your-document_db_username>" \
  knucklessg1/documentdb-mcp:latest
# or, from a clone of this repo:
docker compose -f docker/mcp.compose.yml up -d
```

```json
{
  "mcpServers": {
    "documentdb-mcp": { "url": "http://localhost:8000/mcp" }
  }
}
```

**(c) From a local checkout with `uv`:**

```bash
uv run documentdb-mcp --transport streamable-http --port 8000
```

### 4. Remote URL (deployed behind Caddy)

When the server is deployed remotely (e.g. as a Docker service) and published through
Caddy on the internal `*.arpa` zone, connect with the `"url"` key — no local process or
image required:

```json
{
  "mcpServers": {
    "documentdb-mcp": { "url": "http://documentdb-mcp.arpa/mcp" }
  }
}
```

Caddy reverse-proxies `http://documentdb-mcp.arpa` to the container's `:8000`
streamable-http listener; `http://documentdb-mcp.arpa/health` returns
`{"status":"OK"}` when the service is live.
<!-- END GENERATED: deployment-options -->

This page covers running `documentdb-mcp` as a long-lived server: the transports, a
Docker Compose stack, the integrated agent server, putting it behind a Caddy reverse
proxy, and giving it a DNS name with Technitium. To provision the **DocumentDB**
endpoint it connects to, see [Backing Platform](platform.md).

> `documentdb-mcp` ships both an **MCP server** (console script `documentdb-mcp`) and
> an **A2A agent server** (console script `documentdb-agent`). The MCP server is the
> typed, deterministic tool surface; the agent server is a Pydantic-AI graph agent
> that calls those tools and exposes a web UI.

## Run the MCP server

The transport is selected with `--transport` (or the `TRANSPORT` env var):

=== "stdio (default)"

    ```bash
    documentdb-mcp
    ```
    For IDE / desktop MCP clients that launch the server as a subprocess.

=== "streamable-http"

    ```bash
    documentdb-mcp --transport streamable-http --host 0.0.0.0 --port 8000
    ```
    A network server with a `/health` endpoint and `/mcp` route.

=== "sse"

    ```bash
    documentdb-mcp --transport sse --host 0.0.0.0 --port 8000
    ```

Health check (HTTP transports):

```bash
curl -s http://localhost:8000/health        # {"status":"OK"}
```

## Configuration (environment)

`documentdb-mcp` is configured entirely from the environment. The **required**
connection set:

| Var | Default | Meaning |
|---|---|---|
| `MONGODB_URI` | `mongodb://localhost:27017/` | Full connection URI (takes precedence) |
| `MONGODB_HOST` | `localhost` | Host (used when `MONGODB_URI` is unset) |
| `MONGODB_PORT` | `27017` | Port (used when `MONGODB_URI` is unset) |
| `AUTH_TYPE` | `scram-sha-256` | Authentication mechanism (`scram-sha-1`, `scram-sha-256`, `standard`, `none`) |
| `SYSTEMTOOL` | `True` | Register the system tool module |
| `COLLECTIONSTOOL` | `True` | Register the collections tool module |
| `USERSTOOL` | `True` | Register the users tool module |
| `CRUDTOOL` | `True` | Register the CRUD tool module |
| `ANALYSISTOOL` | `True` | Register the analysis tool module |

Plus `HOST` / `PORT` / `TRANSPORT` for HTTP transports, and the optional telemetry
(`ENABLE_OTEL`, `OTEL_EXPORTER_OTLP_*`) and access-governance (`EUNOMIA_TYPE`,
`EUNOMIA_POLICY_FILE`) variables. The full set is documented in
[`.env.example`](https://github.com/Knuckles-Team/documentdb-mcp/blob/main/.env.example).
Copy it to `.env` and fill in only what you use.

## Docker Compose

The repo ships [`docker/mcp.compose.yml`](https://github.com/Knuckles-Team/documentdb-mcp/blob/main/docker/mcp.compose.yml).
It reads a sibling `.env` and publishes the HTTP server on `:8000`:

```yaml
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
```

```bash
cp .env.example .env          # then edit MONGODB_* values
docker compose -f docker/mcp.compose.yml up -d
docker compose -f docker/mcp.compose.yml logs -f
```

## Agent server

The repo also ships [`docker/agent.compose.yml`](https://github.com/Knuckles-Team/documentdb-mcp/blob/main/docker/agent.compose.yml),
which runs the MCP server alongside the **A2A agent** (console script
`documentdb-agent`). The agent connects back to the MCP server over `MCP_URL` and
publishes its web UI on `:9015`:

```bash
documentdb-agent --provider openai --model-id gpt-4o
```

```yaml
services:
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
```

```bash
docker compose -f docker/agent.compose.yml up -d
```

## Behind a Caddy reverse proxy

Expose the HTTP server on a hostname with automatic TLS. Add to your `Caddyfile`:

```caddy
# Internal (self-signed) — homelab .arpa zone
documentdb-mcp.arpa {
    tls internal
    reverse_proxy documentdb-mcp-mcp:8000
}
```

```caddy
# Public — automatic Let's Encrypt
documentdb-mcp.example.com {
    reverse_proxy documentdb-mcp-mcp:8000
}
```

Reload Caddy:

```bash
docker compose -f services/caddy/compose.yml exec caddy caddy reload --config /etc/caddy/Caddyfile
```

## DNS with Technitium

Point the hostname at the host running Caddy. Via the Technitium API:

```bash
curl -s "http://technitium.arpa:5380/api/zones/records/add" \
  --data-urlencode "token=$TECHNITIUM_DNS_TOKEN" \
  --data-urlencode "domain=documentdb-mcp.arpa" \
  --data-urlencode "zone=arpa" \
  --data-urlencode "type=A" \
  --data-urlencode "ipAddress=10.0.0.10" \
  --data-urlencode "ttl=3600"
```

…or add an **A record** `documentdb-mcp.arpa → <caddy-host-ip>` in the Technitium web
console (`http://technitium.arpa:5380`). The ecosystem
[`technitium-dns-mcp`](https://knuckles-team.github.io/technitium-dns-mcp/) automates
this as a tool.

## Register with an MCP client

Add to your client's `mcp_config.json`:

```json
{
  "mcpServers": {
    "documentdb-mcp": {
      "command": "uv",
      "args": ["run", "documentdb-mcp"],
      "env": {
        "MONGODB_URI": "mongodb://your-documentdb:27017/"
      }
    }
  }
}
```

For a remote HTTP server, point the client at `http://documentdb-mcp.arpa/mcp` instead.
