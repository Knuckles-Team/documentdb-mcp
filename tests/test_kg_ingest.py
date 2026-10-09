"""Knowledge-graph ingestion coverage for the DocumentDB connector.

Exercises the real ``ingest_entities`` / ``ingest_documents`` seam plus the DocumentDB
catalog and collection-document mappers against a fake ``agent_connector_sdk.ingest``
transport (no engine required), asserting the submitted records/relationships and the
record -> :DatabaseServer/:Database/:Collection/:Document mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from agent_connector_sdk.ingest import IngestError, KnowledgeIngest

from documentdb_mcp.kg_ingest import (
    ingest_catalog,
    ingest_collection_documents,
    ingest_documents,
    ingest_entities,
)


class _FakeTransport:
    """Fakes the transport boundary one level below ``KnowledgeIngest``."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    async def source_status(self, connector: str, stream: str) -> Any:
        return SimpleNamespace(accepted_checkpoint=None)

    async def submit(self, request: Any) -> Any:
        self.requests.append(request)
        return SimpleNamespace(
            affected_count=len(request.records),
            relationship_count=len(request.relationships),
        )

    async def store_blob(self, data: bytes) -> str:
        raise AssertionError("this connector's ingestion carries no media")


@pytest.fixture
def ingest() -> tuple[KnowledgeIngest, _FakeTransport]:
    transport = _FakeTransport()
    return KnowledgeIngest(transport, loop=None), transport


class _FakeApi:
    """Minimal stand-in for DocumentDBApi."""

    def binary_version(self):
        return "7.0.0"

    def list_databases(self):
        return ["app"]

    def list_collections(self, database_name):
        assert database_name == "app"
        return ["users"]

    def count_documents(self, database_name, collection_name, filter):
        return 3

    def find(self, database_name, collection_name, filter, limit):
        return [
            {"_id": "abc", "email": "a@b.co"},
            {"_id": "def", "email": "c@d.co"},
            {"no_id": True},
        ]


async def test_ingest_entities_writes_nodes_and_edges(ingest):
    service, transport = ingest
    res = await ingest_entities(
        [
            {"id": "documentdb:database:app", "node_type": "Database", "name": "app"},
            {"id": "documentdb:server:default", "node_type": "DatabaseServer"},
        ],
        [
            {
                "source": "documentdb:database:app",
                "target": "documentdb:server:default",
                "relationship": "hostedOnServer",
            }
        ],
        ingest=service,
    )
    assert res == {"nodes": 2, "edges": 1}
    request = transport.requests[0]
    ids = {record.record_id for record in request.records}
    assert ids == {"documentdb:database:app", "documentdb:server:default"}
    assert request.relationships[0].relation_reference.endswith("/hostedOnServer")


async def test_ingest_documents_maps_document_nodes_and_edges(ingest):
    service, transport = ingest
    res = await ingest_documents(
        [
            {
                "id": "documentdb:document:app.users.abc",
                "text": '{"_id":"abc"}',
                "title": "app.users/abc",
                "_rel": {
                    "source": "documentdb:document:app.users.abc",
                    "target": "documentdb:collection:app.users",
                    "relationship": "inCollection",
                },
            }
        ],
        ingest=service,
    )
    assert res == {"nodes": 1, "edges": 1}
    request = transport.requests[0]
    assert len(request.records) == 1
    assert request.relationships[0].relation_reference.endswith("/inCollection")


async def test_ingest_catalog_maps_server_database_collection(ingest):
    service, transport = ingest
    res = await ingest_catalog(_FakeApi(), ingest=service)
    assert res == {"nodes": 3, "edges": 2}
    request = transport.requests[0]
    by_id = {record.record_id: record for record in request.records}
    assert by_id["documentdb:server:default"].mapping_reference.endswith(
        "/DatabaseServer"
    )
    assert by_id["documentdb:server:default"].payload["serverVersion"] == "7.0.0"
    assert by_id["documentdb:database:app"].mapping_reference.endswith("/Database")
    col = by_id["documentdb:collection:app.users"]
    assert col.mapping_reference.endswith("/Collection")
    assert col.payload["documentCount"] == 3
    assert col.payload["collectionName"] == "users"
    edge_names = {r.relation_reference.rsplit("/", 1)[-1] for r in request.relationships}
    assert edge_names == {"hostedOnServer", "inDatabase"}


async def test_ingest_collection_documents_samples_rows(ingest):
    service, transport = ingest
    res = await ingest_collection_documents(_FakeApi(), "app", "users", ingest=service)
    # 2 rows with _id ingested; the row without _id is skipped.
    assert res == {"nodes": 2, "edges": 2}
    request = transport.requests[0]
    by_id = {record.record_id: record for record in request.records}
    node = by_id["documentdb:document:app.users.abc"]
    assert node.mapping_reference.endswith("/Document")
    # the SDK's governed PII guard redacts uri-shaped values.
    assert node.payload["source_uri"] == "[REDACTED_LOCATION]"
    # the SDK's governed PII guard redacts email-shaped values.
    assert '"email": "[REDACTED_EMAIL]"' in node.payload["text"]
    for rel in request.relationships:
        assert rel.target.record_id == "documentdb:collection:app.users"
        assert rel.relation_reference.endswith("/inCollection")


async def test_ingest_empty_entities_is_rejected(ingest):
    service, _transport = ingest
    with pytest.raises(IngestError, match="at least one entity"):
        await ingest_entities([], ingest=service)


async def test_ingest_empty_documents_is_rejected(ingest):
    service, _transport = ingest
    with pytest.raises(IngestError, match="at least one document"):
        await ingest_documents([], ingest=service)
