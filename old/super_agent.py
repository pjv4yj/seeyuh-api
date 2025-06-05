import asyncio
import os
import shutil
from typing import List

from agents import Agent, Runner, WebSearchTool, function_tool, gen_trace_id, trace
from agents.mcp.server import MCPServer, MCPServerStdio
import subprocess
import asyncio
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
            # Limit output to prevent context window overflow
            max_lines = 50
            max_chars = 3000
            
            lines = output.split('\n')
            if len(lines) > max_lines:
                output = '\n'.join(lines[:max_lines]) + f"\n... (truncated, {len(lines) - max_lines} more lines)"
            
            if len(output) > max_chars:
                output = output[:max_chars] + "... (truncated)"
                
            return f"Command: {command}\n\nOutput ({len(lines)} lines):\n{output}"
        else:
            error_output = result.stderr[:1000]  # Limit error output too
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
    
    # Ghidra Binary Analysis Agent (with shell tools added)
    ghidra_analysis_agent = Agent(
        name="Ghidra Binary Analyst",
        handoff_description="Performs deep binary analysis using Ghidra for reverse engineering and shell commands",
        instructions=(
            f"Use Ghidra tools to perform comprehensive binary analysis AND use shell commands for additional binary inspection. "
            f"The target binary is: {BINARY_PATH}\n"
            f"This binary is already loaded in Ghidra, so you can immediately start analyzing functions.\n\n"
            f"Focus on identifying vulnerable functions, unsafe memory operations, "
            f"buffer overflows, format string vulnerabilities, and other security weaknesses. "
            f"Provide detailed technical analysis with function names, addresses, and risk levels.\n\n"
            f"**ALSO use shell commands to gather additional binary intelligence (USE TARGETED COMMANDS):**\n"
            f"- Basic info: `file {BINARY_PATH}`\n"
            f"- Dependencies: `otool -L {BINARY_PATH}`\n"
            f"- Architecture: `otool -h {BINARY_PATH}`\n"
            f"- Key symbols: `nm {BINARY_PATH} | grep -iE '(message|parse|decode|process|image)' | head -20`\n"
            f"- Parsing strings: `strings {BINARY_PATH} | grep -iE '(format|parse|decode|image|jpeg|png)' | head -20`\n"
            f"- Code signing: `codesign -dv {BINARY_PATH}`\n\n"
            f"**IMPORTANT: Use targeted grep commands to limit output and prevent context overflow.**\n\n"
            f"Combine Ghidra analysis with shell command results for comprehensive assessment."
        ),
        tools=[run_shell_command]
    )
    
    # Vulnerability Reasoning Agent
    vulnerability_reasoning_agent = Agent(
        name="Vulnerability Reasoning Expert", 
        handoff_description="Specialist for reasoning about vulnerability patterns and exploitation potential",
        instructions=(
            "Analyze binary targets and provide detailed reasoning about potential vulnerabilities. "
            "Focus on zero-day indicators like unsafe function calls, memory management issues, "
            "IPC abuse, privilege escalation vectors, and attack surface analysis. "
            "Correlate findings with common vulnerability patterns and exploitation techniques. "
            "Pay special attention to zero-click attack vectors and remote code execution opportunities."
        ),
    )
    
    # Web Search for Known Vulnerabilities (enhanced for zero-click research)
    known_vulnerability_search_agent = Agent(
        name="Known Vulnerability Researcher",
        handoff_description="Searches for known CVEs, exploits, and vulnerability research with focus on zero-click attacks",
        instructions=(
            "Perform comprehensive web searches for known vulnerabilities, CVEs, and security research. "
            "Search for similar binaries, vulnerability patterns, and existing exploits. "
            "Focus on recent disclosures and provide context about exploit availability.\n\n"
            "**PRIORITIZE ZERO-CLICK RESEARCH:**\n"
            "- Search for recent zero-click exploits (FORCEDENTRY, BLASTPASS, etc.)\n"
            "- Look for iMessage and ImageIO vulnerabilities\n"
            "- Research NSO Group and similar advanced persistent threat techniques\n"
            "- Find Project Zero and Citizen Lab vulnerability research\n"
            "- Search for memory corruption bugs in parsing libraries\n\n"
            "Provide specific CVE numbers, attack vectors, and technical details."
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    
    # --- Main Orchestrator Agent ---
    super_agent = Agent(
        name="Super Vulnerability Research Agent",
        instructions=(
            f"You are an elite vulnerability research agent that combines multiple specialized capabilities:\n\n"
            f"**TARGET BINARY:** {BINARY_PATH}\n"
            f"**NOTE:** This binary is already loaded in Ghidra and ready for analysis.\n\n"
            f"1. **Binary Analysis**: Use Ghidra for deep reverse engineering analysis + shell commands for binary inspection\n"
            f"2. **Vulnerability Research**: Search for known CVEs and similar vulnerabilities with focus on zero-click attacks\n" 
            f"3. **Reasoning & Assessment**: Analyze potential zero-day opportunities\n\n"
            f"**Enhanced Workflow for comprehensive analysis:**\n"
            f"1. First, hand off to Ghidra Binary Analyst for technical reverse engineering AND shell-based binary analysis\n"
            f"2. Then, hand off to Known Vulnerability Researcher for CVE research with zero-click focus\n"
            f"3. Next, hand off to Vulnerability Reasoning Expert for pattern analysis\n"
            f"4. Finally, synthesize all findings into a comprehensive vulnerability assessment\n\n"
            f"**Focus Areas:**\n"
            f"- Zero-click attack vectors (especially iMessage/ImageIO)\n"
            f"- Memory corruption vulnerabilities\n"
            f"- Parser bugs in image/document processing\n"
            f"- Remote code execution opportunities\n"
            f"- Sandbox escape mechanisms\n\n"
            f"**Output Format:**\n"
            f"- Executive Summary of findings\n"
            f"- Technical Analysis (functions, addresses, code patterns)\n"
            f"- Vulnerability Assessment (potential zero-days vs known issues)\n"
            f"- Risk Rating and Exploitation Difficulty\n"
            f"- Recommendations for further research\n\n"
            f"Be thorough, technical, and provide actionable intelligence for security researchers."
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
            
            # Update Ghidra specialist agent with MCP server (it already has LocalShellTool)
            for handoff_agent in super_agent.handoffs:
                if handoff_agent.name == "Ghidra Binary Analyst":
                    handoff_agent.mcp_servers = [server]
                # Web search agent already has tools configured
            
            # Generate trace for monitoring
            trace_id = gen_trace_id()
            
            with trace(workflow_name="Super Vulnerability Research", trace_id=trace_id):
                print(f"🔍 Starting Super Vulnerability Analysis")
                print(f"📊 View trace: https://platform.openai.com/traces/trace?trace_id={trace_id}\n")
                print(f"🎯 Query: {query}\n")
                print("=" * 80)
                
                # Run the analysis
                result = await Runner.run(starting_agent=super_agent, input=query)
                
                print("\n" + "=" * 80)
                print("🏆 SUPER VULNERABILITY ANALYSIS COMPLETE")
                print("=" * 80)
                print(result.final_output)
                
                return result
                
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        raise


async def main():
    """Main execution function with example queries"""
    
    # Binary path configuration - easily swappable
    BINARY_PATH = "/System/Applications/Messages.app/Contents/MacOS/Messages"
    
    # Enhanced queries with zero-click focus and hardcoded binary path
    queries = [
        # Enhanced comprehensive analysis with shell tools and zero-click focus
        f"Analyze {BINARY_PATH} (already loaded in Ghidra) for zero-click vulnerabilities. Use shell commands to gather binary intelligence and Ghidra tools to examine functions. Focus on memory corruption bugs in parsing functions. Research FORCEDENTRY/BLASTPASS techniques and find similar patterns. Provide function names, addresses, and exploitation paths.",
        
        # Alternative focused queries
        # "Analyze the binary for iMessage-style zero-click vulnerabilities. Use both Ghidra and shell tools to identify image/document parsing functions, then research similar CVEs.",
        
        # "Hunt for memory corruption vulnerabilities that could enable remote code execution without user interaction. Cross-reference findings with recent zero-click exploit techniques."
    ]
    
    # Run analysis with the first query
    await run_super_analysis(queries[0])


if __name__ == "__main__":
    print("🚀 Initializing Enhanced Vulnerability Research Agent...")
    print("🔧 This agent combines:")
    print("   • Ghidra reverse engineering analysis")
    print("   • Native shell command binary analysis (otool, nm, strings)")
    print("   • Zero-click exploit research and intelligence")
    print("   • Advanced vulnerability pattern recognition")
    print("\n🎯 ENHANCED: Now with shell tools + zero-click focus")
    print("=" * 50)
    
    asyncio.run(main())