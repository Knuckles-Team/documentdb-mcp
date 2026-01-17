---
name: documentdb-mcp-users
description: Documentdb Mcp Users capabilities for A2A Agent.
---
### Overview
This skill provides access to users operations.

### Capabilities
- **create_user**: Create a new user on the specified database.
- **drop_user**: Drop a user from the specified database.
- **update_user**: Update a user's password or roles.
- **users_info**: Get information about a user.

### Common Tools
- `create_user`: Create a new user on the specified database.
- `drop_user`: Drop a user from the specified database.
- `update_user`: Update a user's password or roles.
- `users_info`: Get information about a user.

### Usage Rules
- Use these tools when the user requests actions related to **users**.
- Always interpret the output of these tools to provide a concise summary to the user.

### Example Prompts
- "Please update user"
- "Please drop user"
- "Please users info"
- "Please create user"
