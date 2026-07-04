from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Depends
from pydantic import Field

from documentdb_mcp.auth import get_client


def register_kg_tools(mcp: FastMCP):
    """Register native knowledge-graph ingestion tools (Wire-First, default-on).

    CONCEPT:AU-KG.ingest.enterprise-source-extractor
    """

    @mcp.tool(tags={"misc", "kg"})
    async def documentdb_ingest_catalog(
        database_name: str | None = Field(
            default=None,
            description="Restrict ingestion to a single database (default: all databases).",
        ),
        client=Depends(get_client),
    ) -> dict:
        """Natively ingest the DocumentDB catalog into epistemic-graph as typed nodes.

        Lists databases + collections (with document counts) via the live client and
        pushes ``:DatabaseServer`` / ``:Database`` / ``:Collection`` nodes with their
        ``:hostedOnServer`` / ``:inDatabase`` links. Best-effort: ``{"ingested": None}``
        when no engine is reachable. CONCEPT:AU-KG.ingest.enterprise-source-extractor.
        """
        from documentdb_mcp.kg_ingest import ingest_catalog

        dbs = [database_name] if database_name else None
        result = ingest_catalog(client, database_names=dbs)
        return {"scope": database_name or "all", "ingested": result}

    @mcp.tool(tags={"misc", "kg"})
    async def documentdb_ingest_documents(
        database_name: str = Field(description="Database to sample documents from."),
        collection_name: str = Field(
            description="Collection to sample documents from."
        ),
        filter: dict[str, Any] | None = Field(
            default=None, description="Optional query filter (default: all documents)."
        ),
        limit: int = Field(default=50, description="Max documents to ingest."),
        client=Depends(get_client),
    ) -> dict:
        """Natively ingest stored documents from a collection as ``:Document`` nodes.

        Reads up to ``limit`` rows via ``find`` and pushes each as a ``:Document`` (JSON
        body as searchable text) linked ``:inCollection`` to its ``:Collection``.
        Best-effort: ``{"ingested": None}`` when no engine is reachable.
        CONCEPT:AU-KG.ingest.enterprise-source-extractor.
        """
        from documentdb_mcp.kg_ingest import ingest_collection_documents

        result = ingest_collection_documents(
            client,
            database_name,
            collection_name,
            filter=filter,
            limit=limit,
        )
        return {
            "database": database_name,
            "collection": collection_name,
            "ingested": result,
        }
