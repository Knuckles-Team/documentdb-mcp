"""Capabilities through the SDK (CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001)."""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = ("pyproject.toml", "requirements.txt")


@pytest.mark.spec("CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.1")
def test_driver_comes_from_the_sdk_db_extra() -> None:
    for name in FILES:
        text = (ROOT / name).read_text()
        assert not re.search(r"pymongo\s*[>=<~!]", text), name
    assert "scion-sdk[mcp,db]" in (ROOT / "pyproject.toml").read_text()
    import pymongo  # installed through the SDK db extra

    assert pymongo.version


@pytest.mark.spec("CONN-DOCUMENTDB-MCP-SDK-CENTRALIZATION-R001.2")
def test_sdk_floor_is_current() -> None:
    for name in FILES:
        text = (ROOT / name).read_text()
        floors = re.findall(r"scion-sdk\[[^\]]*\]>=(\d+)\.(\d+)\.(\d+)", text)
        assert floors, name
        assert all(tuple(map(int, f)) >= (0, 5, 6) for f in floors), name
