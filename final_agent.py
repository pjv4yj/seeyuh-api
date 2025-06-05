import asyncio
import os
import shutil
from typing import List

from agents import Agent, Runner, WebSearchTool, function_tool, gen_trace_id, trace
from agents.mcp.server import MCPServer, MCPServerStdio
import subprocess
import asyncio
import os
from pydantic import BaseModel


class VulnerabilityAnalysisResult(BaseModel):
    """Structure for vulnerability analysis results"""
    binary_analysis: str
    potential_vulnerabilities: List[str]
    known_cves: List[str]
    risk_assessment: str


@function_tool
async def run_shell_command(command: str) -> str:
    """Execute a shell command and return the output.
    
    Args:
        command: The shell command to execute (e.g., 'otool -L /path/to/binary')
    
    Returns:
        The command output as a string (limited to prevent context overflow)
    """
    try:
        # Security: Basic command validation to prevent dangerous commands
        dangerous_commands = ['rm ', 'delete', 'format', 'dd ', 'mkfs', 'fdisk']
        if any(dangerous in command.lower() for dangerous in dangerous_commands):
            return f"Error: Command '{command}' contains potentially dangerous operations and is not allowed."
        
        # Execute the command
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=30  # 30 second timeout
        )
        
        if result.returncode == 0:
            output = result.stdout
            # REDUCED limits to prevent token overflow
            max_lines = 20  # Reduced from 50
            max_chars = 1000  # Reduced from 3000
            
            lines = output.split('\n')
            if len(lines) > max_lines:
                output = '\n'.join(lines[:max_lines]) + f"\n... (truncated, {len(lines) - max_lines} more lines)"
            
            if len(output) > max_chars:
                output = output[:max_chars] + "... (truncated)"
                
            return f"Command: {command}\n\nOutput ({len(lines)} lines):\n{output}"
        else:
            error_output = result.stderr[:500]  # Reduced from 1000
            return f"Command: {command}\n\nError (exit code {result.returncode}):\n{error_output}"
            
    except subprocess.TimeoutExpired:
        return f"Error: Command '{command}' timed out after 30 seconds"
    except Exception as e:
        return f"Error executing command '{command}': {str(e)}"


async def create_super_agent() -> Agent:
    """Create the main orchestrator agent with all capabilities"""
    
    # Binary path configuration - easily swappable
    BINARY_PATH = "/System/Applications/Messages.app/Contents/MacOS/Messages"
    
    # --- Specialist Agents ---
    
    # Ghidra Binary Analysis Agent (CONDENSED INSTRUCTIONS)
    ghidra_analysis_agent = Agent(
        name="Ghidra Binary Analyst",
        model="gpt-4o-mini",  # Use mini model to save tokens
        handoff_description="Performs binary analysis using Ghidra and shell commands",
        instructions=(
            f"Analyze {BINARY_PATH} using Ghidra and shell commands. Focus on:\n"
            f"1. Key parsing/message functions (5-8 functions max)\n"
            f"2. Memory management issues\n"
            f"3. Image/document processing\n\n"
            f"Shell commands (run 4-6 total):\n"
            f"- Basic info: `file {BINARY_PATH}`\n"
            f"- Dependencies: `otool -L {BINARY_PATH} | head -10`\n"
            f"- Symbols: `nm {BINARY_PATH} | grep -iE '(parse|image|message)' | head -10`\n"
            f"- Strings: `strings {BINARY_PATH} | grep -iE '(jpeg|png|message)' | head -10`\n\n"
            f"Provide concise analysis with function addresses and vulnerability patterns."
        ),
        tools=[run_shell_command]
    )
    
    # Vulnerability Reasoning Agent (CONDENSED)
    vulnerability_reasoning_agent = Agent(
        name="Vulnerability Reasoning Expert",
        model="gpt-4o-mini",  # Use mini model
        handoff_description="Analyzes vulnerability patterns and exploitation potential",
        instructions=(
            f"Analyze findings for {BINARY_PATH} and identify:\n"
            f"1. Specific vulnerability types (buffer overflow, UAF, etc.)\n"
            f"2. Exploitation scenarios\n"
            f"3. Attack surface assessment\n"
            f"4. Zero-click potential\n\n"
            f"Be concise but thorough. Focus on high-impact findings."
        ),
    )
    
    # Web Search Agent (REDUCED SEARCH COUNT)
    known_vulnerability_search_agent = Agent(
        name="Known Vulnerability Researcher",
        model="gpt-4o-mini",  # Use mini model
        handoff_description="Searches for known CVEs and vulnerability research",
        instructions=(
            f"Research vulnerabilities for Messages app and related frameworks:\n"
            f"1. Recent iMessage/ImageIO CVEs (2022-2025)\n"
            f"2. Zero-click attack techniques\n"
            f"3. Memory corruption in parsing libraries\n\n"
            f"Conduct 3-4 targeted searches maximum. Provide specific CVE numbers and attack vectors."
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    
    # --- Main Orchestrator Agent (SIMPLIFIED) ---
    super_agent = Agent(
        name="Super Vulnerability Research Agent",
        model="gpt-4o-mini",  # Use mini model for orchestration
        instructions=(
            f"Orchestrate vulnerability analysis for {BINARY_PATH}.\n\n"
            f"**WORKFLOW:**\n"
            f"1. Hand off to 'Ghidra Binary Analyst'\n"
            f"2. Hand off to 'Known Vulnerability Researcher'\n"
            f"3. Hand off to 'Vulnerability Reasoning Expert'\n"
            f"4. Synthesize findings\n\n"
            f"Keep coordination brief. Focus on zero-click attacks and memory corruption."
        ),
        handoffs=[
            ghidra_analysis_agent,
            vulnerability_reasoning_agent, 
            known_vulnerability_search_agent
        ],
    )
    
    return super_agent


async def setup_mcp_servers():
    """Setup and return Ghidra MCP server"""
    # Ghidra MCP Server
    ghidra_server = MCPServerStdio(
        name="Ghidra MCP Server",
        params={
            "command": "/Users/pjvann/miniforge3/envs/openai-agents/bin/python3",
            "args": [
                "/Users/pjvann/Desktop/GhidraMCP-release-1-4/bridge_mcp_ghidra.py",
                "--ghidra-server",
                "http://127.0.0.1:8080/"
            ],
        },
    )
    
    return ghidra_server


async def run_super_analysis(query: str):
    """Run comprehensive vulnerability analysis"""
    
    # Validate required paths
    python_path = "/Users/pjvann/miniforge3/envs/openai-agents/bin/python3"
    if not os.path.exists(python_path):
        raise RuntimeError(f"Python executable not found at {python_path}")
    
    bridge_script = "/Users/pjvann/Desktop/GhidraMCP-release-1-4/bridge_mcp_ghidra.py"
    if not os.path.exists(bridge_script):
        raise RuntimeError(f"Ghidra MCP bridge script not found at {bridge_script}")
    
    # Setup MCP server
    ghidra_server = await setup_mcp_servers()
    
    try:
        # Connect to Ghidra MCP server
        async with ghidra_server as server:
            
            # Create super agent with MCP server connection
            super_agent = await create_super_agent()
            super_agent.mcp_servers = [server]
            
            # Update Ghidra specialist agent with MCP server
            for handoff_agent in super_agent.handoffs:
                if handoff_agent.name == "Ghidra Binary Analyst":
                    handoff_agent.mcp_servers = [server]
            
            # Generate trace for monitoring
            trace_id = gen_trace_id()
            
            with trace(workflow_name="Super Vulnerability Research", trace_id=trace_id):
                print(f"🔍 Starting Super Vulnerability Analysis")
                print(f"📊 View trace: https://platform.openai.com/traces/trace?trace_id={trace_id}\n")
                print(f"🎯 Query: {query}\n")
                print("=" * 80)
                
                # Run the analysis with reduced turns
                result = await Runner.run(
                    starting_agent=super_agent, 
                    input=query,
                    max_turns=8  # Reduced from 10
                )
                
                trace_url = f"https://platform.openai.com/traces/trace?trace_id={trace_id}"
                return result.final_output, trace_url 
                
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        raise


async def main_run(BINARY_PATH = "/System/Applications/Messages.app/Contents/MacOS/Messages"):
    """Main execution function with example queries"""
    
    # Verify OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        raise RuntimeError("OPENAI_API_KEY environment variable not set")
    
    # SIMPLIFIED query to reduce token usage
    queries = [
        f"Analyze {BINARY_PATH} for zero-click vulnerabilities. Focus on memory corruption in parsing functions and recent CVEs. Provide specific findings with addresses."
    ]
    
    # Run analysis with the simplified query
    result, trace = await run_super_analysis(queries[0])
    return result, trace