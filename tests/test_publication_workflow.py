"""Consumer contracts for the shared connector delivery workflows."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIPELINES = "Knuckles-Team/pipelines/.github/workflows"


def _workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_pages_workflow_publishes_the_spec_dashboard() -> None:

    config = json.loads((ROOT / ".github/spec-dashboard.json").read_text())
    assert config == {
        "version": 1,
        "sources": [{"glob": "specs/*/status.json", "kind": "spec"}],
    }
    assert sorted((ROOT / "specs").glob("*/status.json"))
    assert not (ROOT / ".github/workflows/docs.yml").exists()


def test_precommit_uses_the_current_connector_gate_aggregate() -> None:
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    pipelines = next(
        repo
        for repo in config["repos"]
        if repo["repo"] == "https://github.com/Knuckles-Team/pipelines"
    )
    hooks = {hook["id"]: hook for hook in pipelines["hooks"]}

    assert pipelines["rev"] == "main"
    assert set(hooks) >= {
        "connector-standard",
        "secrets",
        "spec",
        "tests-fast",
        "dependency-readiness",
    }
    assert hooks["spec"]["stages"] == ["pre-push"]
    assert hooks["tests-fast"]["stages"] == ["pre-push"]
