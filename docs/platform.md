# Backing Platform — DocumentDB

`documentdb-mcp` is a **client** of a DocumentDB (or MongoDB-compatible) endpoint.
This page provides a Docker recipe for deploying one locally to serve as the target
of `MONGODB_URI`. For production topologies, follow the upstream
[DocumentDB documentation](https://github.com/microsoft/documentdb).

!!! note "Backing-system recipe"
    Each connector in the ecosystem follows the same convention — a
    `docs/platform.md` recipe for the system it integrates with, accompanied by a
    sample Compose stack that mirrors [`services/`](https://github.com/Knuckles-Team).
    Systems offered only as a managed service have no local recipe.

## Single-node deployment (Compose)

DocumentDB publishes the `documentdb-local` image. The following stack runs one
node, mirroring the ecosystem [`services/documentdb`](https://github.com/Knuckles-Team)
recipe:

```yaml
# docker/documentdb.compose.yml
services:
  documentdb:
    image: ghcr.io/microsoft/documentdb/documentdb-local:latest
    container_name: documentdb
    hostname: documentdb
    restart: unless-stopped
    environment:
      - USERNAME=admin
      - PASSWORD=change-me
    ports:
      - "10260:10260"          # DocumentDB / MongoDB wire protocol
    volumes:
      - documentdb-data:/data
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  documentdb-data:
```

```bash
docker compose -f docker/documentdb.compose.yml up -d

# Confirm the endpoint answers
docker compose -f docker/documentdb.compose.yml logs -f documentdb
```

## Connect documentdb-mcp

Point the connector's `MONGODB_URI` at the endpoint and supply credentials:

```bash
export MONGODB_URI="mongodb://admin:change-me@localhost:10260/?authMechanism=SCRAM-SHA-256"
export AUTH_TYPE=scram-sha-256

documentdb-mcp --transport streamable-http --host 0.0.0.0 --port 8000
```

## Combined deployment

A combined stack places DocumentDB and the MCP server on one Docker network, so the
server reaches the database by container name:

```yaml
# docker/stack.compose.yml
services:
  documentdb:
    image: ghcr.io/microsoft/documentdb/documentdb-local:latest
    hostname: documentdb
    environment:
      - USERNAME=admin
      - PASSWORD=change-me
    ports: ["10260:10260"]
    volumes: ["documentdb-data:/data"]

  documentdb-mcp:
    image: knucklessg1/documentdb-mcp:latest
    depends_on: [documentdb]
    environment:
      - MONGODB_URI=mongodb://admin:change-me@documentdb:10260/?authMechanism=SCRAM-SHA-256
      - AUTH_TYPE=scram-sha-256
      - TRANSPORT=streamable-http
      - HOST=0.0.0.0
      - PORT=8000
    ports: ["8000:8000"]

volumes:
  documentdb-data:
```

```bash
docker compose -f docker/stack.compose.yml up -d
```

With the database running and reachable, the [MCP tools and `DocumentDBApi`
client](usage.md) operate against it interchangeably with a standard MongoDB
deployment.
