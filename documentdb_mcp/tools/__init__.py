"""Tools that are not client operations (knowledge-graph ingest).

Every database operation is served as its own typed tool derived from the
``DocumentDBApi`` client, so this package holds only the ingest tools.
"""

from documentdb_mcp.tools.kg import register_kg_tools

__all__ = ["register_kg_tools"]
