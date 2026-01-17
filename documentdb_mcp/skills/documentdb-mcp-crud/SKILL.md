---
name: documentdb-mcp-crud
description: Documentdb Mcp Crud capabilities for A2A Agent.
---
### Overview
This skill provides access to crud operations.

### Capabilities
- **insert_one**: Insert a single document into a collection.
- **insert_many**: Insert multiple documents into a collection.
- **find_one**: Find a single document matching the filter.
- **find**: Find documents matching the filter.
- **replace_one**: Replace a single document matching the filter.
- **update_one**: Update a single document matching the filter. 'update' must contain update operators like $set.
- **update_many**: Update multiple documents matching the filter.
- **delete_one**: Delete a single document matching the filter.
- **delete_many**: Delete multiple documents matching the filter.
- **count_documents**: Count documents matching the filter.
- **find_one_and_update**: Finds a single document and updates it. return_document: 'before' or 'after'.
- **find_one_and_replace**: Finds a single document and replaces it. return_document: 'before' or 'after'.
- **find_one_and_delete**: Finds a single document and deletes it.

### Common Tools
- `insert_one`: Insert a single document into a collection.
- `insert_many`: Insert multiple documents into a collection.
- `find_one`: Find a single document matching the filter.
- `find`: Find documents matching the filter.
- `replace_one`: Replace a single document matching the filter.
- `update_one`: Update a single document matching the filter. 'update' must contain update operators like $set.
- `update_many`: Update multiple documents matching the filter.
- `delete_one`: Delete a single document matching the filter.
- `delete_many`: Delete multiple documents matching the filter.
- `count_documents`: Count documents matching the filter.
- `find_one_and_update`: Finds a single document and updates it. return_document: 'before' or 'after'.
- `find_one_and_replace`: Finds a single document and replaces it. return_document: 'before' or 'after'.
- `find_one_and_delete`: Finds a single document and deletes it.

### Usage Rules
- Use these tools when the user requests actions related to **crud**.
- Always interpret the output of these tools to provide a concise summary to the user.

### Example Prompts
- "Please find one"
- "Please find one and update"
- "Please find one and delete"
- "Please delete one"
- "Please update one"
