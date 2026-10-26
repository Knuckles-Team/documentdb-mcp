#!/usr/bin/python
import warnings
from importlib.metadata import version as package_version

from fastmcp.utilities.logging import get_logger

# Filter RequestsDependencyWarning early to prevent log spam
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from requests.exceptions import RequestsDependencyWarning

        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
    except ImportError:
        pass

warnings.filterwarnings("ignore", message=".*urllib3.*or chardet.*")
warnings.filterwarnings("ignore", message=".*urllib3.*or charset_normalizer.*")

import logging
import sys
from typing import Any

from agent_connector_sdk.config import load_config
from agent_connector_sdk.connector import build_server
from starlette.requests import Request
from starlette.responses import JSONResponse

from documentdb_mcp.api_client import DocumentDBApi as DocumentDBApi
from documentdb_mcp.auth import get_client
from documentdb_mcp.tools import (
    register_analysis_tools,  # noqa: F401
    register_collections_tools,  # noqa: F401
    register_crud_tools,  # noqa: F401
    register_kg_tools,  # noqa: F401
    register_system_tools,  # noqa: F401
    register_users_tools,  # noqa: F401
)

__version__ = package_version("documentdb-mcp")

logger = get_logger(name="documentdb-mcp")
logger.setLevel(logging.INFO)


def register_health_route(mcp: Any) -> None:
    """Register the existing backend health route unchanged."""

    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        """Liveness/readiness probe.

        Proves the process is up AND that it can actually reach the
        configured MongoDB-wire backend — a bare ``{"status": "OK"}`` here
        previously reported healthy for weeks while every operation silently
        fell back to an unreachable ``mongodb://localhost:27017`` (dead
        config keys never read by ``auth.get_client``). ``ping`` is the
        standard low-cost MongoDB-wire liveness command; a short
        ``serverSelectionTimeoutMS`` keeps a down backend from hanging the
        k8s probe past its own timeout.
        """
        try:
            client = get_client()
            client.client.admin.command("ping", maxTimeMS=2000)
        except Exception as exc:  # noqa: BLE001 - report any backend failure as degraded
            return JSONResponse(
                {"status": "degraded", "backend": "unreachable", "error": str(exc)},
                status_code=503,
            )
        return JSONResponse({"status": "OK", "backend": "reachable"})


def get_mcp_instance(*, command_args=None) -> tuple[Any, ...]:
    """Preserve legacy configuration while composing the SDK descriptor."""
    load_config()
    args, mcp = build_server("documentdb_mcp", command_args=command_args)
    return mcp, args, list(mcp.middleware)


def mcp_server() -> None:
    """Run the MCP server."""
    mcp, args, middlewares = get_mcp_instance()
    print(f"documentdb-mcp MCP v{__version__}", file=sys.stderr)
    print("\nStarting MCP Server", file=sys.stderr)
    print(f"  Transport: {args.transport.upper()}", file=sys.stderr)
    print(f"  Auth: {args.auth_type}", file=sys.stderr)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.error("Invalid transport", extra={"transport": args.transport})
        sys.exit(1)


if __name__ == "__main__":
    mcp_server()
