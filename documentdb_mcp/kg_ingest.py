"""Native epistemic-graph ingestion for DocumentDB records (typed graph nodes).

CONCEPT:AU-KG.ingest.enterprise-source-extractor. This is the record-source twin of
media-downloader's blob ingestion: the connector natively pushes its catalog into the
ONE epistemic-graph knowledge graph as **typed OWL nodes** (``:DatabaseServer``,
``:Database``, ``:Collection``, ``:DatabaseUser``) plus stored rows as ``:Document``
nodes and their containment links, using the lightweight engine client
(``GraphComputeEngine()._client`` + ``txn``) — the same fast client the blob
``MediaStore`` uses, NOT the heavy in-process ingestion engine.

This module is a **thin mapper** over the shared primitive
``agent_utilities.knowledge_graph.memory.native_ingest``. That primitive is not yet in
the installed ``agent_utilities``, so the write path is import-GUARDED: when the shared
primitive is present it is used; otherwise a self-contained transaction fallback runs.
With no KG stack and no reachable engine every entry point **no-ops** (returns ``None``),
so the connector keeps working with zero KG infrastructure. Node ids follow
``documentdb:<class>:<externalId>`` and every ``type`` matches a class the package's
``documentdb.ttl`` federates.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("documentdb_mcp.kg")

_SOURCE = "documentdb-mcp"
_DOMAIN = "documentdb"
_DEFAULT_GRAPH = "__commons__"
_SERVER_ID = "documentdb:server:default"


def _shared() -> Any | None:
    """Return the shared ``native_ingest`` module, or ``None`` when unavailable."""
    try:
        from agent_utilities.knowledge_graph.memory import (  # type: ignore
            native_ingest,
        )

        return native_ingest
    except Exception as e:  # noqa: BLE001 — primitive not installed yet
        logger.debug("shared native_ingest unavailable: %s", e)
        return None


def _client() -> tuple[Any | None, str]:
    """Return ``(engine_client, graph_name)`` or ``(None, "")`` (self-contained fallback)."""
    try:
        from agent_utilities.knowledge_graph.core.graph_compute import (
            GraphComputeEngine,
        )
    except Exception as e:  # noqa: BLE001 — KG stack absent
        logger.debug("KG ingest unavailable (import): %s", e)
        return None, ""
    try:
        engine = GraphComputeEngine()
        client = getattr(engine, "_client", None)
        if client is None:
            return None, ""
        return client, (getattr(engine, "graph_name", None) or _DEFAULT_GRAPH)
    except Exception as e:  # noqa: BLE001 — engine unreachable
        logger.debug("KG ingest: engine unreachable: %s", e)
        return None, ""


def _write_nodes(
    client: Any,
    graph: str,
    nodes: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None,
    *,
    source: str,
    domain: str,
) -> dict[str, int] | None:
    """Self-contained txn fallback: stamp provenance, MERGE nodes, add edges."""
    nodes = [n for n in nodes if n.get("id")]
    if not nodes:
        return None
    try:
        txn = client.txn.begin(graph=graph)
        for node in nodes:
            props = {k: v for k, v in node.items() if k != "id" and v is not None}
            props.setdefault("source", source)
            props.setdefault("domain", domain)
            client.txn.add_node(txn, node["id"], props)
        committed = client.txn.commit(txn)
    except Exception as e:  # noqa: BLE001 — engine/txn failure is non-fatal
        logger.warning("KG ingest: txn failed: %s", e)
        return None
    if not committed:
        logger.warning("KG ingest: txn not committed (conflict)")
        return None

    edges = 0
    for rel in relationships or []:
        try:
            client.edges.add(
                rel["source"], rel["target"], {"type": rel.get("type", "RELATED")}
            )
            edges += 1
        except Exception as e:  # noqa: BLE001 — pure edge link, best-effort
            logger.debug("KG ingest: edge skipped: %s", e)

    logger.info("KG ingest[%s]: wrote %d nodes, %d edges", domain, len(nodes), edges)
    return {"nodes": len(nodes), "edges": edges}


def ingest_entities(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Write typed OWL nodes (+ edges) into epistemic-graph.

    ``entities``: ``[{"id":..., "type":<owl:Class>, ...props}]``.
    ``relationships``: ``[{"source":id, "target":id, "type":<link>}]``.
    Returns ``{"nodes":n, "edges":m}`` or ``None`` (no engine / failure; never raises).
    ``client``/``graph`` may be injected (tests) — then the self-contained path runs.
    """
    entities = [e for e in (entities or []) if e.get("id")]
    if not entities:
        return None
    if client is None:
        shared = _shared()
        if shared is not None:
            return shared.ingest_entities(
                entities, relationships, source=source, domain=domain
            )
        client, graph = _client()
    if client is None:
        return None
    return _write_nodes(
        client,
        graph or _DEFAULT_GRAPH,
        entities,
        relationships,
        source=source,
        domain=domain,
    )


def ingest_documents(
    documents: list[dict[str, Any]],
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Write text records as ``:Document`` nodes (semantic-search fodder).

    Each doc: ``{"id":..., "text":..., "title"?:..., "source_uri"?:..., ...props}``.
    Returns ``{"nodes":n, "edges":m}`` or ``None``.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    nodes: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []
    for doc in documents or []:
        did = doc.get("id")
        text = doc.get("text") or doc.get("content")
        if not did or not text:
            continue
        node = {
            k: v
            for k, v in doc.items()
            if k not in ("content", "_rel") and v is not None
        }
        node["id"] = did
        node["type"] = "Document"
        node["text"] = text
        node.setdefault("created_at", now)
        nodes.append(node)
        rel = doc.get("_rel")
        if rel:
            rels.append(rel)
    if not nodes:
        return None
    if client is None:
        shared = _shared()
        if shared is not None:
            res = shared.ingest_documents(nodes, source=source, domain=domain)
            # shared primitive does not carry our containment edges; add best-effort.
            if res is not None and rels:
                c2, g2 = _client()
                if c2 is not None:
                    for rel in rels:
                        try:
                            c2.edges.add(
                                rel["source"],
                                rel["target"],
                                {"type": rel.get("type", "RELATED")},
                            )
                        except Exception as e:  # noqa: BLE001
                            logger.debug("KG ingest: doc edge skipped: %s", e)
            return res
        client, graph = _client()
    if client is None:
        return None
    return _write_nodes(
        client, graph or _DEFAULT_GRAPH, nodes, rels, source=source, domain=domain
    )


# --- domain mappers (records -> entity/document dicts) ---------------------------


def ingest_catalog(
    api: Any,
    database_names: list[str] | None = None,
    *,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Map a DocumentDB server's catalog → ``:DatabaseServer``/``:Database``/``:Collection``.

    Lists databases (and, per database, collections + document counts) via the live
    ``api`` client and pushes typed nodes with ``:hostedOnServer`` / ``:inDatabase``
    links. Best-effort: returns ``None`` when no engine is reachable.
    """
    try:
        version = api.binary_version()
    except Exception:  # noqa: BLE001 — version is decorative
        version = None
    entities: list[dict[str, Any]] = [
        {
            "id": _SERVER_ID,
            "type": "DatabaseServer",
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
                "type": "Database",
                "name": db,
                "databaseName": db,
                "externalToolId": db,
            }
        )
        relationships.append(
            {"source": db_id, "target": _SERVER_ID, "type": "hostedOnServer"}
        )
        try:
            collections = api.list_collections(database_name=db)
        except Exception as e:  # noqa: BLE001 — one bad db must not sink the rest
            logger.debug("KG ingest: list_collections(%s) failed: %s", db, e)
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
                    "type": "Collection",
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
                {"source": col_id, "target": db_id, "type": "inDatabase"}
            )
    return ingest_entities(entities, relationships, client=client, graph=graph)


def ingest_collection_documents(
    api: Any,
    database_name: str,
    collection_name: str,
    *,
    filter: dict[str, Any] | None = None,
    limit: int = 50,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Sample rows from a collection → ``:Document`` nodes linked ``:inCollection``.

    The document body is serialized to JSON as the ``:Document`` ``text`` (semantic
    search fodder); the Mongo ``_id`` anchors a stable node id. Best-effort → ``None``.
    """
    col_id = f"documentdb:collection:{database_name}.{collection_name}"
    try:
        rows = api.find(
            database_name=database_name,
            collection_name=collection_name,
            filter=filter or {},
            limit=limit,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "KG ingest: find(%s.%s) failed: %s", database_name, collection_name, e
        )
        return None
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
                "_rel": {"source": doc_id, "target": col_id, "type": "inCollection"},
            }
        )
    return ingest_documents(docs, client=client, graph=graph)
