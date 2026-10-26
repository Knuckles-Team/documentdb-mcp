"""Consumer contracts for the shared connector delivery workflows."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIPELINES = "Knuckles-Team/pipelines/.github/workflows"


def _workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_release_workflow_enables_connector_generation_and_rendering() -> None:
    jobs = _workflow("pipeline.yml")["jobs"]

    assert jobs["publish-pypi"] == {
        "uses": f"{PIPELINES}/python_pipeline.yml@main",
        "with": {"connector": True},
        "permissions": {"contents": "write"},
        "secrets": {"PYPI_API_TOKEN": "${{ secrets.PYPI_API_TOKEN }}"},
    }
    assert jobs["publish-docker"] == {
        "needs": "publish-pypi",
        "uses": f"{PIPELINES}/container_pipeline.yml@main",
        "with": {"render_connector": True},
        "permissions": {"contents": "read"},
        "secrets": {
            "DOCKER_REGISTRY": "${{ secrets.DOCKER_REGISTRY }}",
            "DOCKER_USERNAME": "${{ secrets.DOCKER_USERNAME }}",
            "DOCKER_PASSWORD": "${{ secrets.DOCKER_PASSWORD }}",
            "DOCKER_REPOSITORY": "${{ secrets.DOCKER_REPOSITORY }}",
        },
    }


def test_pages_workflow_publishes_the_spec_dashboard() -> None:
    workflow = _workflow("pages.yml")
    publisher = workflow["jobs"]["publish-pages"]
    paths = workflow[True]["push"]["paths"]

    assert publisher["uses"] == f"{PIPELINES}/pages_pipeline.yml@main"
    assert publisher["with"] == {
        "content_source": "docs",
        "spec_dashboard_enabled": True,
        "spec_dashboard_config": ".github/spec-dashboard.json",
    }
    assert publisher["permissions"] == {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    }
    assert workflow[True]["workflow_dispatch"] == {}
    assert {
        "specs/**",
        ".github/spec-dashboard.json",
        ".github/workflows/pages.yml",
    } <= set(paths)

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
