"""CONN-DOCUMENTDB-MCP-CONNECTOR-CONTENT-R001: the server lists its packaged skills, ontology and prompts by default."""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path

import pytest
from fastmcp import Client

PACKAGE = "documentdb_mcp"
ROOT = Path(list(importlib.import_module(PACKAGE).__path__)[0])

pytestmark = pytest.mark.spec("CONN-DOCUMENTDB-MCP-CONNECTOR-CONTENT-R001")


def _server():
    from unittest.mock import patch

    from fastmcp import FastMCP

    module = importlib.import_module("documentdb_mcp.mcp_server")
    with patch(
        "sys.argv", ["connector", "--transport", "stdio", "--auth-type", "none"]
    ):
        result = module.get_mcp_instance()
    if isinstance(result, FastMCP):
        return result
    return next(value for value in result if isinstance(value, FastMCP))


async def _listings():
    from importlib.metadata import version

    async with Client(_server(), mode="legacy") as client:
        assert client.initialize_result is not None
        assert client.initialize_result.server_info.version == version("documentdb-mcp")
        resources = {str(r.uri) for r in await client.list_resources()}
        prompts = {p.name for p in await client.list_prompts()}
        for uri in resources:
            if uri.startswith(("ontology://", "shapes://")):
                directory = ROOT / "ontology"
                if uri.startswith("shapes://"):
                    directory = directory / "shapes"
                actual = await client.read_resource(uri)
                assert (
                    actual[0].text.encode()
                    == (directory / uri.rsplit("/", 1)[-1]).read_bytes()
                )
    return resources, prompts


def test_default_content_surfaces() -> None:
    resources, prompts = asyncio.run(_listings())
    if list(ROOT.glob("skills/*/SKILL.md")):
        assert any(u.startswith("skill://") for u in resources)
    if list(ROOT.glob("ontology/*.ttl")):
        assert any(u.startswith("ontology://documentdb-mcp/") for u in resources)
    for path in ROOT.glob("prompts/*.json"):
        if not path.name.startswith("_"):
            assert path.stem in prompts


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch):
    import socket

    def refuse(*_args, **_kwargs):
        raise AssertionError("content publication must not contact an external system")

    monkeypatch.setenv("MCP_FLEET_REGISTRATION", "false")
    monkeypatch.setattr(socket.socket, "connect", refuse)


def test_sdk_floor_supports_content_identity_and_current_pack_protocol() -> None:
    import tomllib

    from packaging.requirements import Requirement

    project = tomllib.loads((ROOT.parent / "pyproject.toml").read_text())["project"]
    declared = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared.extend(extra)
    sdk = [Requirement(value) for value in declared if value.startswith("scion-sdk")]
    assert sdk
    for requirement in sdk:
        assert requirement.specifier.contains("0.5.9")
        assert not requirement.specifier.contains("0.5.5")


def test_production_pack_binds_packaged_ontology_and_shapes():
    import hashlib
    from importlib.metadata import version

    from agent_connector_sdk.artifacts.pack import build_content_pack
    from agent_connector_sdk.artifacts.resources import ResourceArtifactKind
    from agent_connector_sdk.ports.session import TransportEndpoint
    from agent_connector_sdk.transports.mcp import McpTransport

    async def capture():
        async with McpTransport().session(
            TransportEndpoint(in_process=_server())
        ) as session:
            return await build_content_pack(
                session, connector="documentdb-mcp", kinds=(ResourceArtifactKind(),)
            )

    pack = asyncio.run(capture())
    assert pack.server_package_version == version("documentdb-mcp")
    entries = {str(entry.uri): entry for entry in pack.archive.entries}
    assert "connector://resources" in entries
    for path in ROOT.glob("ontology/**/*.ttl"):
        scheme = "shapes" if path.parent.name == "shapes" else "ontology"
        uri = f"{scheme}://documentdb-mcp/{path.name}"
        assert entries[uri].body.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_canonical_and_legacy_routes_preserve_the_full_tool_surface():
    from agent_connector_sdk.connector import build_server

    async def capture():
        _, canonical = build_server(
            PACKAGE, command_args=["--transport", "stdio", "--auth-type", "none"]
        )
        async with (
            Client(_server()) as legacy_client,
            Client(canonical) as canonical_client,
        ):
            legacy = {
                tool.name: tool.model_dump(mode="json")
                for tool in await legacy_client.list_tools()
            }
            declared = {
                tool.name: tool.model_dump(mode="json")
                for tool in await canonical_client.list_tools()
            }
        assert len(legacy) == 30
        for name in ("documentdb_ingest_catalog", "documentdb_ingest_documents"):
            assert {"gated", "granular"} <= set(legacy[name]["meta"]["fastmcp"]["tags"])
        assert declared == legacy

    asyncio.run(capture())


def test_legacy_cli_configuration_file_still_controls_host_and_port(
    tmp_path, monkeypatch
):
    import json
    from documentdb_mcp.mcp_server import get_mcp_instance

    config = tmp_path / "connector.json"
    config.write_text(json.dumps({"HOST": "127.0.0.1", "PORT": 9187}))
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setenv("CONNECTOR_CONFIG_FILE", str(config))
    _, args, _ = get_mcp_instance(
        command_args=["--transport", "stdio", "--auth-type", "none"]
    )
    assert (args.host, args.port) == ("127.0.0.1", 9187)
