#!/usr/bin/env python

import importlib
import inspect
from typing import Any

__all__: list[str] = []

CORE_MODULES: list[str] = ["documentdb_mcp.mcp_server"]

OPTIONAL_MODULES = {
    "documentdb_mcp.mcp_server": "mcp",
}


def _expose_members(module):
    """Expose public classes and functions from a module into globals and __all__."""
    for name, obj in inspect.getmembers(module):
        if (inspect.isclass(obj) or inspect.isfunction(obj)) and not name.startswith(
            "_"
        ):
            globals()[name] = obj
            if name not in __all__:
                __all__.append(name)


# Eagerly import core modules (keeps API wrappers fast & light)
for module_name in CORE_MODULES:
    if module_name:
        module = importlib.import_module(module_name)
        _expose_members(module)

# Dynamic/lazy loading of optional modules (agent_server, mcp_server)
_loaded_optional_modules: dict[str, Any] = {}


def _import_module_safely(module_name: str):
    """Try to import a module and return it, or None if not available."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
        return None


def __getattr__(name: str) -> Any:
    # Handle availability flags dynamically without eager imports
    # CONCEPT:AU-ECO.mcp.fastmcp-middleware
    if name == "_MCP_AVAILABLE":
        mcp_key = next((k for k in OPTIONAL_MODULES if "mcp_server" in k), None)
        if mcp_key:
            return _import_module_safely(mcp_key) is not None
        return False

    # Check optional modules
    for module_name in OPTIONAL_MODULES:
        if module_name not in _loaded_optional_modules:
            module = _import_module_safely(module_name)
            if module is not None:
                _loaded_optional_modules[module_name] = module
                _expose_members(module)

        module = _loaded_optional_modules.get(module_name)
        if module is not None and hasattr(module, name):
            return getattr(module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + __all__)


from scion_sdk.connector import Connector
from scion_sdk.connector_hooks import RegistrationContext

from documentdb_mcp.api_client import DocumentDBApi
from documentdb_mcp.auth import get_client


def _register_legacy_health(context: RegistrationContext) -> None:
    """Reuse the existing health route through the public SDK hook."""
    from documentdb_mcp.mcp_server import register_health_route

    register_health_route(context.server)


connector = Connector(
    api=DocumentDBApi,
    get_client=get_client,
    instructions="documentdb-mcp MCP Server — Condensed Action-Routed Tools.",
    extra_registrations=(_register_legacy_health,),
)
