import asyncio
import os
import shutil

from agents import Agent, Runner, gen_trace_id, trace
from agents.mcp.server import MCPServer, MCPServerStdio


async def run(mcp_server: MCPServer):
    agent = Agent(
        name="Assistant",
        instructions="Use the tools to interact with Ghidra and answer questions based on reverse engineering analysis.",
        mcp_servers=[mcp_server],
    )

    # Now run a command to test the connection
    message = "Please analyze the binary file in Ghidra, and identify most vulnerable functions to target for zero day vulnerabilities. Perform extensive analysis."
    print(f"Running: {message}")
    result = await Runner.run(starting_agent=agent, input=message)
    print(result.final_output)


async def main():
    # Connect to your Ghidra MCP server
    async with MCPServerStdio(
        name="Ghidra MCP Server",
        params={
            "command": "/Users/pjvann/miniforge3/envs/openai-agents/bin/python3",
            "args": [
                "/Users/pjvann/Desktop/GhidraMCP-release-1-4/bridge_mcp_ghidra.py",
                "--ghidra-server",
                "http://127.0.0.1:8080/"
            ],
        },
    ) as server:
        trace_id = gen_trace_id()
        with trace(workflow_name="MCP Ghidra Example", trace_id=trace_id):
            print(f"View trace: https://platform.openai.com/traces/trace?trace_id={trace_id}\n")
            await run(server)


if __name__ == "__main__":
    # Check if the Python executable exists
    python_path = "/Users/pjvann/miniforge3/envs/openai-agents/bin/python3"
    if not os.path.exists(python_path):
        raise RuntimeError(f"Python executable not found at {python_path}")
    
    # Check if the Ghidra MCP bridge script exists
    bridge_script = "/Users/pjvann/Desktop/GhidraMCP-release-1-4/bridge_mcp_ghidra.py"
    if not os.path.exists(bridge_script):
        raise RuntimeError(f"Ghidra MCP bridge script not found at {bridge_script}")

    asyncio.run(main())