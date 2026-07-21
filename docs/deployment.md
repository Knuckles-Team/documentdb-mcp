# Deployment

<!-- BEGIN GENERATED: deployment-options -->
## Deployment Options

`documentdb-mcp` supports local stdio, a loopback-only development listener, a
least-privilege stdio container, and a remote authenticated HTTPS boundary.
Provider endpoint, credential, selector, identity, and trust material are supplied
at runtime through `AgentConfig`; none is stored in this repository.

### Installed stdio process

```json
{
  "mcpServers": {
    "documentdb": {
      "command": "documentdb-mcp",
      "args": [],
      "env": {"MCP_TOOL_MODE": "intent"}
    }
  }
}
```

### Loopback development listener

```bash
documentdb-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

Do not expose this listener beyond loopback. Network deployments require direct TLS
or an explicitly trusted TLS-terminating ingress, configured authentication, exact
`MCP_ALLOWED_HOSTS`, and an exact trusted-proxy CIDR policy.

### Least-privilege local container

```bash
docker run -i --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -e TRANSPORT=stdio \
  registry.example.invalid/documentdb-mcp@sha256:<digest> documentdb-mcp
```

The operator projects the selected AgentConfig profile into the process at runtime;
the image remains immutable and contains no environment connection profile.

### Remote authenticated HTTPS endpoint

```json
{
  "mcpServers": {
    "documentdb": {"url": "https://service.example.invalid/mcp"}
  }
}
```

Store the real remote URL, outbound identity reference, and TLS-profile reference in
`AgentConfig`, not in MCP client JSON or documentation.
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
    image: example/documentdb-mcp@sha256:<digest>
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
    image: example/documentdb-mcp@sha256:<digest>
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
# Internal (self-signed) — homelab .example.invalid zone
documentdb-mcp.example.invalid {
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
curl -s "http://technitium.example.invalid:5380/api/zones/records/add" \
  --data-urlencode "token=$TECHNITIUM_DNS_TOKEN" \
  --data-urlencode "domain=documentdb-mcp.example.invalid" \
  --data-urlencode "zone=arpa" \
  --data-urlencode "type=A" \
  --data-urlencode "ipAddress=192.0.2.10" \
  --data-urlencode "ttl=3600"
```

…or add an **A record** `documentdb-mcp.example.invalid → <caddy-host-ip>` in the Technitium web
console (`http://technitium.example.invalid:5380`). The ecosystem
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

For a remote HTTP server, point the client at `http://documentdb-mcp.example.invalid/mcp` instead.
