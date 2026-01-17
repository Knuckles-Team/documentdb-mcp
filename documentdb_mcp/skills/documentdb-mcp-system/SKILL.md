---
name: documentdb-mcp-system
description: Documentdb Mcp System capabilities for A2A Agent.
---
### Overview
This skill provides access to system operations.

### Capabilities
- **binary_version**: Get the binary version of the server (using buildInfo).
- **list_databases**: List all databases in the connected DocumentDB/MongoDB instance.
- **run_command**: Run a raw command against the database.

### Common Tools
- `binary_version`: Get the binary version of the server (using buildInfo).
- `list_databases`: List all databases in the connected DocumentDB/MongoDB instance.
- `run_command`: Run a raw command against the database.

### Usage Rules
- Use these tools when the user requests actions related to **system**.
- Always interpret the output of these tools to provide a concise summary to the user.

### Example Prompts
- "Please list databases"
- "Please run command"
- "Please binary version"
