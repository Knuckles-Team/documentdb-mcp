"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` seam plus the DocumentDB
catalog and collection-document mappers with a fake engine client + a fake API client
(no engine required), asserting the txn add_node/commit + edge calls and the
record -> :DatabaseServer/:Database/:Collection/:Document mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

import pytest
from agent_utilities.knowledge_graph.memory.native_ingest import NativeIngestError

from documentdb_mcp.kg_ingest import (
    ingest_catalog,
    ingest_collection_documents,
    ingest_documents,
    ingest_entities,
)


class _FakeTxn:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.committed = False

    def begin(self, graph=None):
        self.graph = graph
        return "txn-1"

    def add_node(self, txn, node_id, props):
        self.nodes[node_id] = props

    def add_edge(self, txn, src, dst, props):
        self.edges.append((src, dst, props))

    def commit(self, txn):
        self.committed = True
        return True



class _FakeClient:
    def __init__(self):
        self.txn = _FakeTxn()


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
        graph="__commons__",
    )
    assert res == {"nodes": 2, "edges": 1}
    assert c.txn.committed is True
    assert set(c.txn.nodes) == {"documentdb:database:app", "documentdb:server:default"}
    # provenance stamped
    assert c.txn.nodes["documentdb:database:app"]["source"] == "documentdb-mcp"
    assert c.txn.nodes["documentdb:database:app"]["domain"] == "documentdb"
    assert c.txn.edges == [
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
        graph="__commons__",
    )
    assert res == {"nodes": 1, "edges": 1}
    node = c.txn.nodes["documentdb:document:app.users.abc"]
    assert node["node_type"] == "Document"
    assert "_rel" not in node
    assert node["needs_enrichment"] is True
    assert c.txn.edges[0][2] == {"relationship": "inCollection"}


def test_ingest_catalog_maps_server_database_collection():
    c = _FakeClient()
    res = ingest_catalog(_FakeApi(), client=c, graph="__commons__")
    assert res == {"nodes": 3, "edges": 2}
    assert c.txn.nodes["documentdb:server:default"]["node_type"] == "DatabaseServer"
    assert c.txn.nodes["documentdb:server:default"]["serverVersion"] == "7.0.0"
    assert c.txn.nodes["documentdb:database:app"]["node_type"] == "Database"
    col = c.txn.nodes["documentdb:collection:app.users"]
    assert col["node_type"] == "Collection"
    assert col["documentCount"] == 3
    assert col["collectionName"] == "users"
    edge_types = sorted(e[2]["relationship"] for e in c.txn.edges)
    assert edge_types == ["hostedOnServer", "inDatabase"]


def test_ingest_collection_documents_samples_rows():
    c = _FakeClient()
    res = ingest_collection_documents(
        _FakeApi(), "app", "users", client=c, graph="__commons__"
    )
    # 2 rows with _id ingested; the row without _id is skipped.
    assert res == {"nodes": 2, "edges": 2}
    assert c.txn.nodes["documentdb:document:app.users.abc"]["node_type"] == "Document"
    node = c.txn.nodes["documentdb:document:app.users.abc"]
    assert node["source_uri"] == "documentdb://app/users/abc"
    assert '"email": "a@b.co"' in node["text"]
    for e in c.txn.edges:
        assert e[1] == "documentdb:collection:app.users"
        assert e[2] == {"relationship": "inCollection"}


def test_ingest_rejects_legacy_structural_fields():
    with pytest.raises(NativeIngestError, match="canonical node_type"):
        ingest_entities([{"id": "legacy", "type": "Legacy"}], client=_FakeClient())

def test_ingest_empty_is_rejected():
    with pytest.raises(NativeIngestError, match="at least one entity"):
        ingest_entities([], client=_FakeClient())
