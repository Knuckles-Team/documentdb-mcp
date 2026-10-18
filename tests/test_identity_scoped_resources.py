"""Identity-scoped database auto-load (CONCEPT:AU-OS.identity.identity-scoped-resource-autoload).

``documentdb_system(action="list_databases")`` routes the returned database
names through the shared agent-connector-sdk entitlement resolver so a caller's
Okta/Keycloak groups scope which databases they see. The resolver itself is
tested in agent-connector-sdk; here we mock the entitlement source (per the
container-manager-mcp reference pattern) and test the local filtering logic
plus its fail-open degrade when agent-connector-sdk predates the resolver.
"""

import sys
import types

import pytest

from documentdb_mcp.tools.system import _entitled


def _install_fake_entitlements(entitled_names):
    """Install a fake ``agent_connector_sdk.security.entitlements`` module."""
    module = types.ModuleType("agent_connector_sdk.entitlements")
    setattr(  # noqa: B010 - dynamic attribute on a faked module for test isolation
        module,
        "identity_scoped_resources",
        lambda namespace, names: [n for n in names if n in entitled_names],
    )
    sys.modules["agent_connector_sdk.entitlements"] = module


@pytest.fixture(autouse=True)
def _cleanup_fake_module():
    yield
    sys.modules.pop("agent_connector_sdk.entitlements", None)


class TestEntitledHelper:
    def test_filters_to_entitled_subset(self):
        _install_fake_entitlements({"prod"})
        assert _entitled("db", ["prod", "staging", "dev"]) == ["prod"]

    def test_no_entitlements_returns_empty(self):
        _install_fake_entitlements(set())
        assert _entitled("db", ["prod", "dev"]) == []

    def test_degrades_to_full_set_without_resolver(self):
        # No identity bound -> the SDK raises IdentityRequiredError -> unscoped
        # full set (today's local behaviour), not fail closed.
        sys.modules.pop("agent_connector_sdk.entitlements", None)
        assert _entitled("db", ["prod", "dev"]) == ["prod", "dev"]
