"""Native epistemic-graph ingestion for DocumentDB records (typed graph nodes).

CONCEPT:AU-KG.ingest.enterprise-source-extractor. This is the record-source twin of
media-downloader's blob ingestion: the connector natively pushes its catalog into the
ONE epistemic-graph knowledge graph as **typed OWL nodes** (``:DatabaseServer``,
``:Database``, ``:Collection``, ``:DatabaseUser``) plus stored rows as ``:Document``
nodes and their containment links through the ``agent_connector_sdk.ingest``
knowledge-ingest facade. Node ids follow ``documentdb:<class>:<externalId>`` and every
``node_type`` matches a class the package's ``documentdb.ttl`` federates.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_connector_sdk.ingest import (
    ChangeSet,
    Document,
    Entity,
    IngestBinding,
    IngestError,
    KnowledgeIngest,
    Relationship,
    current_ingest,
)

logger = logging.getLogger("documentdb_mcp.kg")

_BINDING = IngestBinding(connector="documentdb-mcp", stream="documentdb")
_SERVER_ID = "documentdb:server:default"


def _to_entity(record: dict[str, Any]) -> Entity:
    return Entity(
        id=record.get("id"),
        node_type=record.get("node_type"),
        properties={k: v for k, v in record.items() if k not in ("id", "node_type")},
    )


def _to_relationship(record: dict[str, Any]) -> Relationship:
    props = {
        k: v for k, v in record.items() if k not in ("source", "target", "relationship")
    }
    return Relationship(
        source=record.get("source"),
        target=record.get("target"),
        relationship=record.get("relationship"),
        properties=props or None,
    )


def _to_document(record: dict[str, Any]) -> Document:
    return Document(
        id=record.get("id"),
        text=record.get("text"),
        title=record.get("title"),
        source_uri=record.get("source_uri"),
        properties={
            k: v
            for k, v in record.items()
            if k not in ("id", "text", "title", "source_uri")
        },
    )


async def ingest_entities(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
    *,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Write canonical typed nodes and relationships through the SDK's ingest facade."""
    if not entities:
        raise IngestError("ingest_entities needs at least one entity")
    change_set = ChangeSet(
        entities=tuple(_to_entity(e) for e in entities),
        relationships=tuple(_to_relationship(r) for r in relationships or ()),
    )
    service = ingest or current_ingest()
    receipt = await service.submit(_BINDING, change_set)
    return {"nodes": receipt.affected_count, "edges": receipt.relationship_count}


async def ingest_documents(
    documents: list[dict[str, Any]],
    *,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Write text records as ``:Document`` nodes (semantic-search fodder).

    Each doc: ``{"id":..., "text":..., "title"?:..., "source_uri"?:..., ...props}``.
    An optional ``_rel`` key (``{"source":..., "target":..., "relationship":...}``)
    is pulled off and submitted as a containment relationship alongside the document.
    """
    docs: list[Document] = []
    rels: list[Relationship] = []
    for doc in documents or []:
        did = doc.get("id")
        text = doc.get("text") or doc.get("content")
        if not did or not text:
            continue
        rel = doc.get("_rel")
        clean = {
            k: v for k, v in doc.items() if k not in ("content", "_rel") and v is not None
        }
        clean["id"] = did
        clean["text"] = text
        docs.append(_to_document(clean))
        if rel:
            rels.append(_to_relationship(rel))
    if not docs:
        raise IngestError("ingest_documents needs at least one document")
    change_set = ChangeSet(documents=tuple(docs), relationships=tuple(rels))
    service = ingest or current_ingest()
    receipt = await service.submit(_BINDING, change_set)
    return {"nodes": receipt.affected_count, "edges": receipt.relationship_count}


# --- domain mappers (records -> entity/document dicts) ---------------------------


async def ingest_catalog(
    api: Any,
    database_names: list[str] | None = None,
    *,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Map a DocumentDB server's catalog → ``:DatabaseServer``/``:Database``/``:Collection``.

    Lists databases (and, per database, collections + document counts) via the live
    ``api`` client and pushes typed nodes with ``:hostedOnServer`` / ``:inDatabase``
    links. Source and SDK ingest failures propagate.
    """
    try:
        version = api.binary_version()
    except Exception:  # noqa: BLE001 — version is decorative
        version = None
    entities: list[dict[str, Any]] = [
        {
            "id": _SERVER_ID,
            "node_type": "DatabaseServer",
            "name": "DocumentDB server",
            "serverVersion": version,
            "externalToolId": "default",
        }
    ]
    relationships: list[dict[str, Any]] = []

    dbs = database_names if database_names is not None else api.list_databases()
    for db in dbs or []:
        if not db:
            continue
        db_id = f"documentdb:database:{db}"
        entities.append(
            {
                "id": db_id,
                "node_type": "Database",
                "name": db,
                "databaseName": db,
                "externalToolId": db,
            }
        )
        relationships.append(
            {
                "source": db_id,
                "target": _SERVER_ID,
                "relationship": "hostedOnServer",
            }
        )
        try:
            collections = api.list_collections(database_name=db)
        except Exception as e:  # noqa: BLE001 — one bad db must not sink the rest
            logger.debug("Operation failed: error_type=%s", type(e).__name__)
            continue
        for col in collections or []:
            if not col:
                continue
            col_id = f"documentdb:collection:{db}.{col}"
            try:
                count = api.count_documents(
                    database_name=db, collection_name=col, filter={}
                )
            except Exception:  # noqa: BLE001
                count = None
            entities.append(
                {
                    "id": col_id,
                    "node_type": "Collection",
                    "name": col,
                    "collectionName": col,
                    "databaseName": db,
                    "documentCount": count
                    if isinstance(count, int) and count >= 0
                    else None,
                    "externalToolId": f"{db}.{col}",
                }
            )
            relationships.append(
                {"source": col_id, "target": db_id, "relationship": "inDatabase"}
            )
    return await ingest_entities(entities, relationships, ingest=ingest)


async def ingest_collection_documents(
    api: Any,
    database_name: str,
    collection_name: str,
    *,
    filter: dict[str, Any] | None = None,
    limit: int = 50,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Sample rows from a collection → ``:Document`` nodes linked ``:inCollection``.

    The document body is serialized to JSON as the ``:Document`` ``text`` (semantic
    search fodder); the Mongo ``_id`` anchors a stable node id.
    """
    col_id = f"documentdb:collection:{database_name}.{collection_name}"
    rows = api.find(
        database_name=database_name,
        collection_name=collection_name,
        filter=filter or {},
        limit=limit,
    )
    docs: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        oid = str(row.get("_id") or "")
        if not oid:
            continue
        doc_id = f"documentdb:document:{database_name}.{collection_name}.{oid}"
        docs.append(
            {
                "id": doc_id,
                "text": json.dumps(row, ensure_ascii=False, default=str),
                "title": f"{database_name}.{collection_name}/{oid}",
                "source_uri": f"documentdb://{database_name}/{collection_name}/{oid}",
                "databaseName": database_name,
                "collectionName": collection_name,
                "_rel": {
                    "source": doc_id,
                    "target": col_id,
                    "relationship": "inCollection",
                },
            }
        )
    return await ingest_documents(docs, ingest=ingest)
