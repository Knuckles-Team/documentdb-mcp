"""DocumentDB graph configuration — tag prompts and env var mappings.

This is the only file needed to enable graph mode for this agent.
Provides TAG_PROMPTS and TAG_ENV_VARS for create_graph_agent_server().
"""

                                                                       
TAG_PROMPTS: dict[str, str] = {
    "analysis": (
        "You are a DocumentDB Analysis specialist. Help users manage and interact with Analysis functionality using the available tools."
    ),
    "collections": (
        "You are a DocumentDB Collections specialist. Help users manage and interact with Collections functionality using the available tools."
    ),
    "crud": (
        "You are a DocumentDB Crud specialist. Help users manage and interact with Crud functionality using the available tools."
    ),
    "system": (
        "You are a DocumentDB System specialist. Help users manage and interact with System functionality using the available tools."
    ),
    "users": (
        "You are a DocumentDB Users specialist. Help users manage and interact with Users functionality using the available tools."
    ),
}


                                                                        
TAG_ENV_VARS: dict[str, str] = {
    "analysis": "ANALYSISTOOL",
    "collections": "COLLECTIONSTOOL",
    "crud": "CRUDTOOL",
    "system": "SYSTEMTOOL",
    "users": "USERSTOOL",
}
