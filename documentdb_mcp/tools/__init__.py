"""Tools package containing modular FastMCP tool registration functions.

CONCEPT:ECO-4.1
"""

from documentdb_mcp.tools.analysis import register_analysis_tools
from documentdb_mcp.tools.collections import register_collections_tools
from documentdb_mcp.tools.crud import register_crud_tools
from documentdb_mcp.tools.system import register_system_tools
from documentdb_mcp.tools.users import register_users_tools

__all__ = [
    "register_system_tools",
    "register_collections_tools",
    "register_users_tools",
    "register_crud_tools",
    "register_analysis_tools",
]
