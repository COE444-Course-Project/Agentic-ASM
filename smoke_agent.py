import sys
import asyncio
from pathlib import Path
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

TOOL = Path(__file__).resolve().parent / "tools" / "http_server.py"

async def main():
    client = MultiServerMCPClient({
        "http": {"command": sys.executable,
                 "args": [str(TOOL)],
                 "transport": "stdio"}
    })
    tools = await client.get_tools()
    agent = create_react_agent(ChatOllama(model="qwen2.5", temperature=0), tools)
    result = await agent.ainvoke({"messages": [(
        "user",
        "Using the http_request tool, GET http://localhost:5001/users/v1 "
        "and list the usernames you find."
    )]})
    print(result["messages"][-1].content)

asyncio.run(main())