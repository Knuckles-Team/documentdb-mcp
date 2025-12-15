# DocumentDB - A2A & MCP Server

![PyPI - Version](https://img.shields.io/pypi/v/documentdb-mcp)
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

*Version: 0.0.3*

DocumentDB + MCP Server + A2A

A [FastMCP](https://github.com/jlowin/fastmcp) server and A2A (Agent-to-Agent) agent for [DocumentDB](https://documentdb.io/).
DocumentDB is a MongoDB-compatible open source document database built on PostgreSQL.

This package provides:
1.  **MCP Server**: Exposes DocumentDB functionality (CRUD, Administration) as tools for LLMs.
2.  **A2A Agent**: A specialized agent that uses these tools to help users manage their database.

## Features

-   **CRUD Operations**: Insert, Find, Update, Replace, Delete, Count, Distinct, Aggregate.
-   **Collection Management**: Create, Drop, List, Rename collections.
-   **User Management**: Create, Update, Drop users.
-   **Direct Commands**: Run raw database commands.


### MCP CLI

| Short Flag | Long Flag                       | Description                                                                                               |
|------------|---------------------------------|-----------------------------------------------------------------------------------------------------------|
| -h         | --help                          | Display help information                                                                                  |
| -t         | --transport                     | Transport method: 'stdio', 'http', or 'sse' [legacy] (default: stdio)                                     |
| -s         | --host                          | Host address for HTTP transport (default: 0.0.0.0)                                                        |
| -p         | --port                          | Port number for HTTP transport (default: 8000)                                                            |
|            | --auth-type                     | Authentication type: 'none', 'static', 'jwt', 'oauth-proxy', 'oidc-proxy', 'remote-oauth' (default: none) |
|            | --token-jwks-uri                | JWKS URI for JWT verification                                                                             |
|            | --token-issuer                  | Issuer for JWT verification                                                                               |
|            | --token-audience                | Audience for JWT verification                                                                             |
|            | --token-algorithm               | JWT signing algorithm (e.g., HS256, RS256). Required for HMAC or static keys. Auto-detected for JWKS.     |
|            | --token-secret                  | Shared secret for HMAC (HS*) verification. Used with --token-algorithm.                                   |
|            | --token-public-key              | Path to PEM public key file or inline PEM string for static asymmetric verification.                      |
|            | --required-scopes               | Comma-separated required scopes (e.g., documentdb.read,documentdb.write). Enforced by JWTVerifier.        |
|            | --oauth-upstream-auth-endpoint  | Upstream authorization endpoint for OAuth Proxy                                                           |
|            | --oauth-upstream-token-endpoint | Upstream token endpoint for OAuth Proxy                                                                   |
|            | --oauth-upstream-client-id      | Upstream client ID for OAuth Proxy                                                                        |
|            | --oauth-upstream-client-secret  | Upstream client secret for OAuth Proxy                                                                    |
|            | --oauth-base-url                | Base URL for OAuth Proxy                                                                                  |
|            | --oidc-config-url               | OIDC configuration URL                                                                                    |
|            | --oidc-client-id                | OIDC client ID                                                                                            |
|            | --oidc-client-secret            | OIDC client secret                                                                                        |
|            | --oidc-base-url                 | Base URL for OIDC Proxy                                                                                   |
|            | --remote-auth-servers           | Comma-separated list of authorization servers for Remote OAuth                                            |
|            | --remote-base-url               | Base URL for Remote OAuth                                                                                 |
|            | --allowed-client-redirect-uris  | Comma-separated list of allowed client redirect URIs                                                      |
|            | --eunomia-type                  | Eunomia authorization type: 'none', 'embedded', 'remote' (default: none)                                  |
|            | --eunomia-policy-file           | Policy file for embedded Eunomia (default: mcp_policies.json)                                             |
|            | --eunomia-remote-url            | URL for remote Eunomia server                                                                             |
|            | --enable-delegation             | Enable OIDC token delegation to (default: False)                                                          |
|            | --audience                      | Audience for the delegated token                                                                          |
|            | --delegated-scopes              | Scopes for the delegated token (space-separated)                                                          |
|            | --openapi-file                  | Path to OpenAPI JSON spec to import tools/resources from                                                  |
|            | --openapi-base-url              | Base URL for the OpenAPI client (defaults to instance URL)                                                |

### A2A CLI

| Short Flag | Long Flag         | Description                                                            |
|------------|-------------------|------------------------------------------------------------------------|
| -h         | --help            | Display help information                                               |
|            | --host            | Host to bind the server to (default: 0.0.0.0)                          |
|            | --port            | Port to bind the server to (default: 9000)                             |
|            | --reload          | Enable auto-reload                                                     |
|            | --provider        | LLM Provider: 'openai', 'anthropic', 'google', 'huggingface'           |
|            | --model-id        | LLM Model ID (default: qwen3:4b)                                       |
|            | --base-url        | LLM Base URL (for OpenAI compatible providers)                         |
|            | --api-key         | LLM API Key                                                            |
|            | --mcp-url         | MCP Server URL (default: http://localhost:8000/mcp)                    |

## Installation

```bash
pip install documentdb-mcp
```

## Usage

### 1. DocumentDB MCP Server

The MCP server connects to your DocumentDB (or MongoDB) instance.

**Environment Variables:**

-   `MONGODB_URI`: Connection string (e.g., `mongodb://localhost:27017/`).
-   Alternatively: `MONGODB_HOST` (default: `localhost`) and `MONGODB_PORT` (default: `27017`).

**Running the Server:**

```bash
# Stdio mode (default)
documentdb-mcp

# HTTP mode
documentdb-mcp --transport http --port 8000
```

### 2. DocumentDB A2A Agent

The A2A agent connects to the MCP server to perform tasks.

**Environment Variables:**

-   `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`: API key for your chosen LLM provider.
-   `OPENAI_BASE_URL`: (Optional) Base URL for OpenAI-compatible providers (e.g. Ollama).

**Running the Agent:**

```bash
# Start Agent Server (Default: OpenAI/Ollama)
documentdb-a2a

# Custom Configuration
documentdb-a2a --provider anthropic --model-id claude-3-5-sonnet-20240620 --mcp-url http://localhost:8000/mcp
```

## Docker Utils

To run with Docker using the provided `Dockerfile`:

```bash
docker build -t documentdb-mcp .
docker run -e MONGODB_URI=mongodb://host.docker.internal:27017/ -p 8000:8000 documentdb-mcp
```



## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests or verification
python -m build
```
