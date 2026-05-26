"""Tools package containing modular FastMCP tool registration functions.

CONCEPT:ECO-4.1
"""

from documentdb_mcp.mcp.analysis import register_analysis_tools
from documentdb_mcp.mcp.collections import register_collections_tools
from documentdb_mcp.mcp.crud import register_crud_tools
from documentdb_mcp.mcp.system import register_system_tools
from documentdb_mcp.mcp.users import register_users_tools

__all__ = [
    "register_system_tools",
    "register_collections_tools",
    "register_users_tools",
    "register_crud_tools",
    "register_analysis_tools",
]
