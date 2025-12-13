# DocumentDB MCP Server & A2A Agent

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

## Installation

```bash
pip install .
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
