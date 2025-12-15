import os
import argparse
import uvicorn
from typing import List, Optional
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.huggingface import HuggingFaceModel
from pydantic_ai.toolsets.fastmcp import FastMCPToolset
from fasta2a import Skill

# Default Configuration
DEFAULT_PROVIDER = os.getenv("PROVIDER", "openai")
DEFAULT_MODEL_ID = os.getenv("MODEL_ID", "qwen3:4b")
DEFAULT_OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "http://ollama.arpa/v1")
DEFAULT_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "ollama")
DEFAULT_MCP_URL = os.getenv("MCP_URL", "http://documentdb-mcp.arpa/mcp")
DEFAULT_ALLOWED_TOOLS: List[str] = [
    "list_databases",
    "list_collections",
    "create_collection",
    "drop_collection",
    "insert_one",
    "find_one",
    "find",
    "update_one",
    "delete_one",
    "aggregate",
]

AGENT_NAME = "DocumentDBAgent"
AGENT_DESCRIPTION = (
    "A specialist agent for managing and querying DocumentDB (MongoDB-compatible)."
)
INSTRUCTIONS = (
    "You are a database administrator and query specialist for DocumentDB.\n\n"
    "Your primary goal is to assist users in managing their database collections and performing queries.\n"
    "You have access to a rich set of tools for CRUD operations and collection management.\n\n"
    "Key Guidelines:\n"
    "- When asked to find data, prefer using 'find' with appropriate filters.\n"
    "- For complex analysis, utilize the 'aggregate' tool with a proper pipeline.\n"
    "- Always verify collection existence with 'list_collections' if you are unsure.\n"
    "- Be careful with destructive operations like 'drop_collection' or 'delete_many'. Ask for confirmation if the request seems ambiguous or risky.\n"
    "- Format your output clearly, especially when presenting query results.\n\n"
    "Handle errors gracefully: if a query fails, check the error message and suggest a fix (e.g., malformed JSON filter)."
)


def create_agent(
    provider: str = DEFAULT_PROVIDER,
    model_id: str = DEFAULT_MODEL_ID,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    mcp_url: str = DEFAULT_MCP_URL,
    allowed_tools: List[str] = DEFAULT_ALLOWED_TOOLS,
) -> Agent:
    """
    Factory function to create the AGENT_NAME with configuration.
    """
    # Define the model based on provider
    model = None

    if provider == "openai":
        target_base_url = base_url or DEFAULT_OPENAI_BASE_URL
        target_api_key = api_key or DEFAULT_OPENAI_API_KEY

        if target_base_url:
            os.environ["OPENAI_BASE_URL"] = target_base_url
        if target_api_key:
            os.environ["OPENAI_API_KEY"] = target_api_key
        model = OpenAIChatModel(model_id, provider="openai")

    elif provider == "anthropic":
        if api_key:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        model = AnthropicModel(model_id)

    elif provider == "google":
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key
            os.environ["GOOGLE_API_KEY"] = api_key
        model = GoogleModel(model_id)

    elif provider == "huggingface":
        if api_key:
            os.environ["HF_TOKEN"] = api_key
        model = HuggingFaceModel(model_id)

    else:
        raise ValueError(f"Unsupported provider: {provider}")

    # Define the toolset using FastMCPToolset
    try:
        toolset = FastMCPToolset(client=mcp_url)
        filtered_toolset = toolset.filtered(
            lambda ctx, tool_def: tool_def.name in allowed_tools
        )
        toolsets = [filtered_toolset]
    except Exception as e:
        print(
            f"Warning: Could not connect to MCP server at {mcp_url}. Agent will start without tools. Error: {e}"
        )
        toolsets = []

    # Define the agent
    agent_definition = Agent(
        model,
        system_prompt=INSTRUCTIONS,
        name=AGENT_NAME,
        toolsets=toolsets,
    )

    return agent_definition


# Expose as A2A server (Default instance for ASGI runners)
# Note: This default instance might fail to connect to MCP if it's not up,
# but that's expected behavior for static analysis or simple imports.
agent = create_agent()

# Define skills for the Agent Card
skills = [
    Skill(
        id="crud_operations",
        name="CRUD Operations",
        description="Create, Read, Update, and Delete documents in DocumentDB.",
        tags=["database", "crud", "mongodb"],
        examples=["Find users with age > 25", "Insert a new order"],
        input_modes=["text"],
        output_modes=["text", "json"],
    ),
    Skill(
        id="aggregation",
        name="Aggregation Pipeline",
        description="Run complex aggregation pipelines for data analysis.",
        tags=["database", "analysis"],
        examples=["Calculate average sales per region"],
        input_modes=["text"],
        output_modes=["text", "json"],
    ),
    Skill(
        id="collection_management",
        name="Collection Management",
        description="Create, drop, and list collections.",
        tags=["database", "admin"],
        examples=["Create a 'logs' collection", "List all collections"],
        input_modes=["text"],
        output_modes=["text"],
    ),
]


def agent_server():
    parser = argparse.ArgumentParser(description=f"Run the {AGENT_NAME} A2A Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the server to")
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to bind the server to"
    )
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    parser.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        choices=["openai", "anthropic", "google", "huggingface"],
        help="LLM Provider",
    )
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID, help="LLM Model ID")
    parser.add_argument(
        "--base-url",
        default=None,
        help="LLM Base URL (for OpenAI compatible providers)",
    )
    parser.add_argument("--api-key", default=None, help="LLM API Key")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help="MCP Server URL")
    parser.add_argument(
        "--allowed-tools",
        nargs="*",
        default=DEFAULT_ALLOWED_TOOLS,
        help="List of allowed MCP tools",
    )

    args = parser.parse_args()

    base_url = args.base_url
    api_key = args.api_key

    if args.provider == "openai":
        if base_url is None:
            base_url = DEFAULT_OPENAI_BASE_URL
        if api_key is None:
            api_key = DEFAULT_OPENAI_API_KEY

    print(
        f"Starting {AGENT_NAME} with provider={args.provider}, model={args.model_id}, mcp={args.mcp_url}"
    )

    cli_agent = create_agent(
        provider=args.provider,
        model_id=args.model_id,
        base_url=base_url,
        api_key=api_key,
        mcp_url=args.mcp_url,
        allowed_tools=args.allowed_tools,
    )

    # Version 0.1.0 since this is a new implementation
    cli_app = cli_agent.to_a2a(
        name=AGENT_NAME, description=AGENT_DESCRIPTION, version="0.0.5", skills=skills
    )

    uvicorn.run(
        cli_app,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    agent_server()
