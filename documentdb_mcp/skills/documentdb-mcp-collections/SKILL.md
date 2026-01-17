---
name: documentdb-mcp-collections
description: Documentdb Mcp Collections capabilities for A2A Agent.
---
### Overview
This skill provides access to collections operations.

### Capabilities
- **list_collections**: List all collections in a specific database.
- **create_collection**: Create a new collection in the specified database.
- **drop_collection**: Drop a collection from the specified database.
- **create_database**: Explicitly create a database by creating a collection in it (MongoDB creates DBs lazily).
- **drop_database**: Drop a database.
- **rename_collection**: Rename a collection.

### Common Tools
- `list_collections`: List all collections in a specific database.
- `create_collection`: Create a new collection in the specified database.
- `drop_collection`: Drop a collection from the specified database.
- `create_database`: Explicitly create a database by creating a collection in it (MongoDB creates DBs lazily).
- `drop_database`: Drop a database.
- `rename_collection`: Rename a collection.

### Usage Rules
- Use these tools when the user requests actions related to **collections**.
- Always interpret the output of these tools to provide a concise summary to the user.

### Example Prompts
- "Please drop collection"
- "Please list collections"
- "Please create database"
- "Please rename collection"
- "Please drop database"
