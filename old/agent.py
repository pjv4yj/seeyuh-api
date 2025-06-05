from agents import Agent, Runner, WebSearchTool, MCPServerStdio
from pydantic import BaseModel
import asyncio
from agents.mcp import MCPServer, MCPServerStdio

# --- Agent: Reasoning Expert ---
vulnerability_reasoning_agent = Agent(
    name="Vulnerability Reasoning Expert",
    handoff_description="Specialist agent for reasoning about macOS vulnerabilities",
    instructions=(
        "You analyze macOS binary targets and provide detailed reasoning about potential vulnerabilities. "
        "Focus on zero-day indicators like unsafe function calls, memory management, and IPC abuse."
    ),
)

# --- Agent: Known Vulnerability Search ---
known_vulnerability_search_agent = Agent(
    name="Known Vulnerability Search",
    handoff_description="Performs a web search for known CVEs or similar patterns",
    instructions="Given a binary target or area of concern, perform a web search for known vulnerabilities or related CVEs.",
    tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
)

# --- Triage Agent: Routes to the right expert ---
triage_agent = Agent(
    name="Triage Agent",
    instructions="Decide whether the user's question is about reasoning through new vulnerabilities or checking known CVEs online. Route accordingly.",
    handoffs=[vulnerability_reasoning_agent, known_vulnerability_search_agent],
)

# --- Main Execution ---
async def main():

    async with MCPServerStdio(
        params={
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/jason/Desktop/macos_vulnerabilities"],
        }
    ) as server:
        tools = await server.list_tools()
        print(tools)

    user_query = "Tell me about known MacOS vulnerabilities (most recent ones please)"
    result = await Runner.run(triage_agent, user_query)
    print("Final Output:\n", result.final_output)

if __name__ == "__main__":
    asyncio.run(main())
