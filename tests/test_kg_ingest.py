"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` seam plus the DocumentDB
catalog and collection-document mappers with a fake engine client + a fake API client
(no engine required), asserting the txn add_node/commit + edge calls and the
record -> :DatabaseServer/:Database/:Collection/:Document mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

from typing import Any

import msgpack
import pytest
from agent_utilities.knowledge_graph.memory.native_ingest import NativeIngestError
from agent_utilities.security.brain_context import ActorContext, use_actor
from agent_utilities.models.company_brain import ActorType
from agent_utilities.knowledge_graph.core.session import GraphSession, use_session

from documentdb_mcp.kg_ingest import (
    ingest_catalog,
    ingest_collection_documents,
    ingest_documents,
    ingest_entities,
)


@pytest.fixture(autouse=True)
def _governed_session():
    actor = ActorContext(
        actor_id="subject:opaque:synthetic",
        actor_type=ActorType.AUTOMATED_SERVICE,
        roles=(),
        tenant_id="tenant:opaque:synthetic",
        authenticated=True,
    )
    session = GraphSession(
        actor=actor,
        tenant=actor.tenant_id,
        scopes=frozenset({"kg:write"}),
        graph="graph:opaque:synthetic",
        policy_version="policy:opaque:synthetic",
        audience="epistemic-graph",
    )
    with use_actor(actor), use_session(session):
        yield


class _FakeNodes:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}

    def properties(self, node_id: str) -> dict[str, Any] | None:
        return self.values.get(node_id)

    def list(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.values.items())


class _FakeChanges:
    def __init__(self, nodes: _FakeNodes) -> None:
        self.nodes = nodes
        self.edges: list[tuple[str, str, dict[str, Any]]] = []
        self.applied: list[dict[str, Any]] = []
        self.records: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, dict[str, Any]] = {}

    def get(self, envelope_id: str) -> dict[str, Any] | None:
        return self.records.get(envelope_id)

    def content_version(self, object_id: str) -> dict[str, Any] | None:
        return self.versions.get(object_id)

    def cursor(self, _source: str, _partition: str = "") -> None:
        return None

    def apply(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(envelope)
        mutation = envelope["mutation"]
        for operation in mutation["operations"]:
            method = operation["method"]
            params = method["params"]
            properties = msgpack.unpackb(params["properties_msgpack"], raw=False)
            if method["method"] == "AddNode":
                self.nodes.values[params["node_id"]] = properties
            elif method["method"] == "AddEdge":
                self.edges.append(
                    (params["source_id"], params["target_id"], properties)
                )
        version = envelope["content_version"]
        self.versions[version["object_id"]] = version
        self.records[envelope["envelope_id"]] = envelope
        return {
            "batch_id": mutation["batch_id"],
            "replayed": False,
            "projection_pending": False,
        }


class _FakeRdf:
    def validate_shacl(self, _shapes: str, _data_graph: str) -> dict[str, Any]:
        return {"conforms": True, "results": []}


class _FakeClient:
    def __init__(self) -> None:
        self.nodes = _FakeNodes()
        self.changes = _FakeChanges(self.nodes)
        self.rdf = _FakeRdf()

    @staticmethod
    def supports(operation: str) -> bool:
        return operation == "ApplyChangeEnvelope"


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


def test_ingest_entities_writes_nodes_and_edges():
    c = _FakeClient()
    res = ingest_entities(
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
        client=c,
    )
    assert res == {"nodes": 2, "edges": 1}
    assert len(c.changes.applied) == 1
    assert set(c.nodes.values) == {"documentdb:database:app", "documentdb:server:default"}
    # provenance stamped
    assert c.nodes.values["documentdb:database:app"]["source"] == "documentdb-mcp"
    assert c.nodes.values["documentdb:database:app"]["domain"] == "documentdb"
    assert c.changes.edges == [
        (
            "documentdb:database:app",
            "documentdb:server:default",
            {"relationship": "hostedOnServer"},
        )
    ]


def test_ingest_documents_maps_document_nodes_and_edges():
    c = _FakeClient()
    res = ingest_documents(
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
        client=c,
    )
    assert res == {"nodes": 1, "edges": 1}
    node = c.nodes.values["documentdb:document:app.users.abc"]
    assert node["node_type"] == "Document"
    assert "_rel" not in node
    assert node["needs_enrichment"] is True
    assert c.changes.edges[0][2] == {"relationship": "inCollection"}


def test_ingest_catalog_maps_server_database_collection():
    c = _FakeClient()
    res = ingest_catalog(_FakeApi(), client=c)
    assert res == {"nodes": 3, "edges": 2}
    assert c.nodes.values["documentdb:server:default"]["node_type"] == "DatabaseServer"
    assert c.nodes.values["documentdb:server:default"]["serverVersion"] == "7.0.0"
    assert c.nodes.values["documentdb:database:app"]["node_type"] == "Database"
    col = c.nodes.values["documentdb:collection:app.users"]
    assert col["node_type"] == "Collection"
    assert col["documentCount"] == 3
    assert col["collectionName"] == "users"
    edge_types = sorted(e[2]["relationship"] for e in c.changes.edges)
    assert edge_types == ["hostedOnServer", "inDatabase"]


def test_ingest_collection_documents_samples_rows():
    c = _FakeClient()
    res = ingest_collection_documents(
        _FakeApi(), "app", "users", client=c
    )
    # 2 rows with _id ingested; the row without _id is skipped.
    assert res == {"nodes": 2, "edges": 2}
    assert c.nodes.values["documentdb:document:app.users.abc"]["node_type"] == "Document"
    node = c.nodes.values["documentdb:document:app.users.abc"]
    # native_ingest's governed PII scrubber redacts uri-shaped values.
    assert node["source_uri"] == "[REDACTED_LOCATION]"
    # native_ingest's governed PII scrubber redacts email-shaped values.
    assert '"email": "[REDACTED_EMAIL]"' in node["text"]
    for e in c.changes.edges:
        assert e[1] == "documentdb:collection:app.users"
        assert e[2] == {"relationship": "inCollection"}


def test_ingest_rejects_legacy_structural_fields():
    with pytest.raises(NativeIngestError, match="canonical node_type"):
        ingest_entities([{"id": "legacy", "type": "Legacy"}], client=_FakeClient())

def test_ingest_empty_is_rejected():
    with pytest.raises(NativeIngestError, match="at least one entity"):
        ingest_entities([], client=_FakeClient())
