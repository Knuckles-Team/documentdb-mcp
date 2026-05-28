#!/usr/bin/python
import warnings

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
import os
import sys
from typing import Any

from agent_utilities.base_utilities import to_boolean
from agent_utilities.mcp_utilities import create_mcp_server
from dotenv import find_dotenv, load_dotenv
from starlette.requests import Request
from starlette.responses import JSONResponse

from documentdb_mcp.auth import get_client  # noqa: F401
from documentdb_mcp.tools import (
    register_analysis_tools,
    register_collections_tools,
    register_crud_tools,
    register_system_tools,
    register_users_tools,
)

__version__ = "0.15.0"

logger = get_logger(name="documentdb-mcp")
logger.setLevel(logging.INFO)


def get_mcp_instance() -> tuple[Any, ...]:
    """Initialize and return the MCP instance."""
    load_dotenv(find_dotenv())
    args, mcp, middlewares = create_mcp_server(
        name="documentdb-mcp MCP",
        version=__version__,
        instructions="documentdb-mcp MCP Server — Condensed Action-Routed Tools.",
    )

    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "OK"})

    DEFAULT_SYSTEMTOOL = to_boolean(os.getenv("SYSTEMTOOL", "True"))
    if DEFAULT_SYSTEMTOOL:
        register_system_tools(mcp)
    DEFAULT_COLLECTIONSTOOL = to_boolean(os.getenv("COLLECTIONSTOOL", "True"))
    if DEFAULT_COLLECTIONSTOOL:
        register_collections_tools(mcp)
    DEFAULT_USERSTOOL = to_boolean(os.getenv("USERSTOOL", "True"))
    if DEFAULT_USERSTOOL:
        register_users_tools(mcp)
    DEFAULT_CRUDTOOL = to_boolean(os.getenv("CRUDTOOL", "True"))
    if DEFAULT_CRUDTOOL:
        register_crud_tools(mcp)
    DEFAULT_ANALYSISTOOL = to_boolean(os.getenv("ANALYSISTOOL", "True"))
    if DEFAULT_ANALYSISTOOL:
        register_analysis_tools(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)
    return mcp, args, middlewares


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
