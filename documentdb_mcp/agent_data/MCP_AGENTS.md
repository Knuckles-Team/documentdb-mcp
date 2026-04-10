# MCP_AGENTS.md - Dynamic Agent Registry

This file tracks the generated agents from MCP servers. You can manually modify the 'Tools' list to customize agent expertise.

## Agent Mapping Table

| Name | Description | System Prompt | Tools | Tag | Source MCP |
|------|-------------|---------------|-------|-----|------------|
| Documentdb Analysis Specialist | Expert specialist for analysis domain tasks. | You are a Documentdb Analysis specialist. Help users manage and interact with Analysis functionality using the available tools. | documentdb-mcp_analysis_toolset | analysis | documentdb-mcp |
| Documentdb Users Specialist | Expert specialist for users domain tasks. | You are a Documentdb Users specialist. Help users manage and interact with Users functionality using the available tools. | documentdb-mcp_users_toolset | users | documentdb-mcp |
| Documentdb System Specialist | Expert specialist for system domain tasks. | You are a Documentdb System specialist. Help users manage and interact with System functionality using the available tools. | documentdb-mcp_system_toolset | system | documentdb-mcp |
| Documentdb Collections Specialist | Expert specialist for collections domain tasks. | You are a Documentdb Collections specialist. Help users manage and interact with Collections functionality using the available tools. | documentdb-mcp_collections_toolset | collections | documentdb-mcp |
| Documentdb Crud Specialist | Expert specialist for crud domain tasks. | You are a Documentdb Crud specialist. Help users manage and interact with Crud functionality using the available tools. | documentdb-mcp_crud_toolset | crud | documentdb-mcp |
| Documentdb Misc Specialist | Expert specialist for misc domain tasks. | You are a Documentdb Misc specialist. Help users manage and interact with Misc functionality using the available tools. | documentdb-mcp_misc_toolset | misc | documentdb-mcp |

## Tool Inventory Table

| Tool Name | Description | Tag | Source |
|-----------|-------------|-----|--------|
| documentdb-mcp_analysis_toolset | Static hint toolset for analysis based on config env. | analysis | documentdb-mcp |
| documentdb-mcp_users_toolset | Static hint toolset for users based on config env. | users | documentdb-mcp |
| documentdb-mcp_system_toolset | Static hint toolset for system based on config env. | system | documentdb-mcp |
| documentdb-mcp_collections_toolset | Static hint toolset for collections based on config env. | collections | documentdb-mcp |
| documentdb-mcp_crud_toolset | Static hint toolset for crud based on config env. | crud | documentdb-mcp |
| documentdb-mcp_misc_toolset | Static hint toolset for misc based on config env. | misc | documentdb-mcp |
