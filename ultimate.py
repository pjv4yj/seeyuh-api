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
        model="gpt-4o-mini",  # Explicitly specify model
        handoff_description="Performs deep binary analysis using Ghidra for reverse engineering and shell commands",
        instructions=(
            f"Use Ghidra tools to perform comprehensive binary analysis AND use shell commands for additional binary inspection. "
            f"The target binary is: {BINARY_PATH}\n"
            f"This binary is already loaded in Ghidra, so you can immediately start analyzing functions.\n\n"
            f"**EXTENSIVE ANALYSIS REQUIREMENTS:**\n"
            f"- Use Ghidra to examine ALL functions related to parsing, images, messages\n"
            f"- Analyze AT LEAST 10-15 functions thoroughly\n"
            f"- Look for vulnerability patterns in EACH function\n"
            f"- Provide function addresses, parameter analysis, and risk assessment\n"
            f"- Continue until you've covered major attack surfaces\n\n"
            f"**DYNAMIC SHELL COMMAND STRATEGY:**\n"
            f"Start with basic commands, then decide what to investigate further:\n"
            f"1. Basic info: `file {BINARY_PATH}`\n"
            f"2. Dependencies: `otool -L {BINARY_PATH}`\n"
            f"3. Architecture: `otool -h {BINARY_PATH}`\n"
            f"4. Code signing: `codesign -dv {BINARY_PATH}`\n\n"
            f"**THEN, based on what you find, investigate further with targeted searches:**\n"
            f"- If you find CoreGraphics: `nm {BINARY_PATH} | grep -i coregraphics | head -20`\n"
            f"- If you find ImageIO: `strings {BINARY_PATH} | grep -i imageio | head -20`\n"
            f"- If you find parsing functions: `nm {BINARY_PATH} | grep -iE '(parse|decode|decompress)' | head -20`\n"
            f"- If you find message handling: `strings {BINARY_PATH} | grep -iE '(message|chat|balloon)' | head -20`\n"
            f"- If you find image formats: `strings {BINARY_PATH} | grep -iE '(jpeg|png|gif|heic|webp)' | head -20`\n"
            f"- If you find memory functions: `nm {BINARY_PATH} | grep -iE '(malloc|free|copy|alloc)' | head -20`\n\n"
            f"**REASONING-DRIVEN INVESTIGATION:**\n"
            f"- Look at the Ghidra function analysis and decide which areas need deeper shell investigation\n"
            f"- Use shell commands to validate and expand on Ghidra findings\n"
            f"- If you find suspicious functions, search for related strings/symbols\n"
            f"- Adapt your shell commands based on what vulnerabilities you're investigating\n\n"
            f"**IMPORTANT:** Run 8-12 shell commands total, making intelligent decisions about what to investigate.\n"
            f"Combine Ghidra analysis with shell command results for comprehensive assessment."
        ),
        tools=[run_shell_command]
    )
    
    # Vulnerability Reasoning Agent
    vulnerability_reasoning_agent = Agent(
        name="Vulnerability Reasoning Expert",
        model="gpt-4o",  # Explicitly specify model
        handoff_description="Specialist for reasoning about vulnerability patterns and exploitation potential",
        instructions=(
            f"You are a vulnerability reasoning specialist analyzing {BINARY_PATH}. "
            f"Analyze binary targets and provide detailed reasoning about potential vulnerabilities. "
            f"Focus on zero-day indicators like unsafe function calls, memory management issues, "
            f"IPC abuse, privilege escalation vectors, and attack surface analysis. "
            f"Correlate findings with common vulnerability patterns and exploitation techniques. "
            f"Pay special attention to zero-click attack vectors and remote code execution opportunities.\n\n"
            f"**DEEP ANALYSIS REQUIREMENTS:**\n"
            f"- Examine EVERY function provided by previous agents\n"
            f"- Identify specific vulnerability types (buffer overflow, UAF, etc.)\n"
            f"- Trace data flows and attack surfaces\n"
            f"- Assess exploitability and impact\n"
            f"- Provide exploitation scenarios\n"
            f"- Reference similar CVEs and attack techniques\n"
            f"- Continue analysis until you've covered all findings thoroughly"
        ),
    )
    
    # Web Search for Known Vulnerabilities (enhanced for zero-click research)
    known_vulnerability_search_agent = Agent(
        name="Known Vulnerability Researcher",
        model="gpt-4o",  # Explicitly specify model
        handoff_description="Searches for known CVEs, exploits, and vulnerability research with focus on zero-click attacks",
        instructions=(
            f"You are a vulnerability intelligence specialist researching zero-click attacks. "
            f"Perform comprehensive web searches for known vulnerabilities, CVEs, and security research. "
            f"Search for similar binaries, vulnerability patterns, and existing exploits. "
            f"Focus on recent disclosures and provide context about exploit availability.\n\n"
            f"**COMPREHENSIVE RESEARCH REQUIREMENTS:**\n"
            f"- Search for MULTIPLE queries to build complete intelligence\n"
            f"- Research recent zero-click exploits (FORCEDENTRY, BLASTPASS, etc.)\n"
            f"- Look for iMessage and ImageIO vulnerabilities (2020-2025)\n"
            f"- Research NSO Group and similar advanced persistent threat techniques\n"
            f"- Find Project Zero and Citizen Lab vulnerability research\n"
            f"- Search for memory corruption bugs in parsing libraries\n"
            f"- Look for macOS Messages app specific vulnerabilities\n"
            f"- Research ImageIO, CoreGraphics, and related framework CVEs\n"
            f"- Find exploitation techniques and proof-of-concepts\n\n"
            f"**CONDUCT AT LEAST 5-8 SEARCHES** to gather comprehensive intelligence.\n"
            f"Provide specific CVE numbers, attack vectors, and technical details."
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    
    # --- Main Orchestrator Agent ---
    super_agent = Agent(
        name="Super Vulnerability Research Agent",
        instructions=(
            f"You are an elite vulnerability research agent orchestrating a comprehensive analysis.\n\n"
            f"**TARGET BINARY:** {BINARY_PATH}\n"
            f"**NOTE:** This binary is already loaded in Ghidra and ready for analysis.\n\n"
            f"**YOUR JOB:** Coordinate sequential handoffs to build comprehensive vulnerability intelligence.\n\n"
            f"**REQUIRED WORKFLOW (Execute in Order):**\n\n"
            f"🔄 **TURN 1:** Hand off to 'Ghidra Binary Analyst' for deep technical analysis\n"
            f"🔄 **TURN 2:** Hand off to 'Known Vulnerability Researcher' for CVE intelligence\n"
            f"🔄 **TURN 3:** Hand off to 'Vulnerability Reasoning Expert' for pattern analysis\n"
            f"🔄 **TURN 4:** Synthesize all findings into comprehensive assessment\n\n"
            f"**EXECUTION RULES:**\n"
            f"- Make ONE handoff per turn\n"
            f"- After each specialist completes, immediately decide on next handoff\n"
            f"- Do NOT summarize or analyze between handoffs - just coordinate\n"
            f"- Keep making handoffs until all specialists have provided results\n"
            f"- Your role is ORCHESTRATION, not analysis\n\n"
            f"**DECISION LOGIC:**\n"
            f"- If this is the start: Hand off to 'Ghidra Binary Analyst'\n"
            f"- If you just received Ghidra results: Hand off to 'Known Vulnerability Researcher'\n"
            f"- If you just received web research: Hand off to 'Vulnerability Reasoning Expert'\n"
            f"- If you have all three results: Provide final comprehensive synthesis\n\n"
            f"**CRITICAL:** Keep the workflow moving - don't stop after one handoff!\n\n"
            f"**Focus Areas for Final Synthesis:**\n"
            f"- Zero-click attack vectors (especially iMessage/ImageIO)\n"
            f"- Memory corruption vulnerabilities\n"
            f"- Parser bugs in image/document processing\n"
            f"- Remote code execution opportunities\n"
            f"- Sandbox escape mechanisms"
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
                
                # Run the analysis with more turns to allow multiple handoffs
                result = await Runner.run(
                    starting_agent=super_agent, 
                    input=query,
                    max_turns=10  # Allow multiple turns for sequential handoffs
                )
                
                #print("\n" + "=" * 80)
                #print("🏆 SUPER VULNERABILITY ANALYSIS COMPLETE")
                #print("=" * 80)
                print(result.final_output)
                
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
    
    
    # Enhanced queries with zero-click focus and hardcoded binary path
    queries = [
        # Enhanced comprehensive analysis with shell tools and zero-click focus
        f"Hunt for zero-click vulnerabilities in {BINARY_PATH}. Start with CVE research to guide targeted Ghidra analysis. Focus on memory corruption and parsing bugs. Provide specific functions, addresses, and exploitation paths.",
        
        # Alternative focused queries
        # "Analyze the binary for iMessage-style zero-click vulnerabilities. Use both Ghidra and shell tools to identify image/document parsing functions, then research similar CVEs.",
        
        # "Hunt for memory corruption vulnerabilities that could enable remote code execution without user interaction. Cross-reference findings with recent zero-click exploit techniques."
    ]
    
    # Run analysis with the first query
    result, trace = await run_super_analysis(queries[0])
    return result, trace


if __name__ == "__main__":
    print("🚀 Initializing Enhanced Vulnerability Research Agent...")
    print("🔧 This agent combines:")
    print("   • Ghidra reverse engineering analysis")
    print("   • Native shell command binary analysis (otool, nm, strings)")
    print("   • Zero-click exploit research and intelligence")
    print("   • Advanced vulnerability pattern recognition")
    print("\n🎯 ENHANCED: Now with shell tools + zero-click focus")
    print("=" * 50)
    
    # Run the analysis and get structured results
    results, trace = asyncio.run(main_run())