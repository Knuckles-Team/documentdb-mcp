"""PIPE-CONNSPEC-R116.4: the DocumentDB development skill is packaged."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "documentdb_mcp/skills/documentdb-mcp-development/SKILL.md"

pytestmark = pytest.mark.spec("PIPE-CONNSPEC-R116.4")


def test_development_skill_has_rapid_contract_and_package_binding() -> None:
    text = SKILL.read_text(encoding="utf-8")
    frontmatter = text.split("---", 2)[1]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    lockfile = (ROOT / "uv.lock").read_text(encoding="utf-8")

    assert SKILL.is_file()
    assert re.search(r"^name:\s*documentdb-mcp-development\s*$", frontmatter, re.M)
    assert re.search(r"^skill_type:\s*skill\s*$", frontmatter, re.M)
    assert "## Rapid delivery: the 5-minute contract" in text
    for term in (
        "documentdb_mcp/__init__.py",
        "documentdb_mcp/api_client.py",
        "documentdb_mcp/api/",
        "documentdb_mcp/auth.py",
        "documentdb_mcp/mcp_server.py",
        "documentdb_mcp/tools/",
        "documentdb_mcp/connector_sources.py",
        "documentdb_mcp/kg_ingest.py",
        "documentdb_mcp/ontology/",
        "MONGODB_URI",
        "MONGODB_HOST",
        "MONGODB_PORT",
        "documentdb-mcp",
        "documentdb_system",
        "documentdb_collections",
        "documentdb_users",
        "documentdb_crud",
        "documentdb_analysis",
        "documentdb_ingest_catalog",
        "documentdb_ingest_documents",
        "connector://resources",
        "skills/**",
        "python_pipeline.yml@main",
        "connector: true",
        "container_pipeline.yml@main",
        "render_connector: true",
        "pages_pipeline.yml@main",
        "uv run --locked --extra test pytest",
    ):
        assert term in text

    assert "verify=False" not in text
    assert "--no-verify" not in text
    package_data = project["tool"]["setuptools"]["package-data"]["documentdb_mcp"]
    assert "skills/**" in package_data
    assert project["project"]["entry-points"]["scion_sdk.connector"] == {
        "documentdb-mcp": "documentdb_mcp:connector"
    }
    assert re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.M)
    assert "packaged DocumentDB connector development skill" in changelog
    assert re.search(
        rf'(?ms)^name = "documentdb-mcp"\nversion = "{re.escape(version)}"\n',
        lockfile,
    )
