import asyncio
import os
import shutil
from typing import List

from agents import Agent, Runner, WebSearchTool, gen_trace_id, trace
from agents.mcp.server import MCPServer, MCPServerStdio
from pydantic import BaseModel


class VulnerabilityAnalysisResult(BaseModel):
    """Structure for vulnerability analysis results"""
    binary_analysis: str
    potential_vulnerabilities: List[str]
    known_cves: List[str]
    risk_assessment: str


async def create_super_agent() -> Agent:
    """Create the main orchestrator agent with all capabilities"""
    
    # --- Specialist Agents ---
    
    # Ghidra Binary Analysis Agent
    ghidra_analysis_agent = Agent(
        name="Ghidra Binary Analyst",
        handoff_description="Performs deep binary analysis using Ghidra for reverse engineering",
        instructions=(
            "Use Ghidra tools to perform comprehensive binary analysis. "
            "Focus on identifying vulnerable functions, unsafe memory operations, "
            "buffer overflows, format string vulnerabilities, and other security weaknesses. "
            "Provide detailed technical analysis with function names, addresses, and risk levels."
        ),
    )
    
    # Vulnerability Reasoning Agent
    vulnerability_reasoning_agent = Agent(
        name="Vulnerability Reasoning Expert", 
        handoff_description="Specialist for reasoning about vulnerability patterns and exploitation potential",
        instructions=(
            "Analyze binary targets and provide detailed reasoning about potential vulnerabilities. "
            "Focus on zero-day indicators like unsafe function calls, memory management issues, "
            "IPC abuse, privilege escalation vectors, and attack surface analysis. "
            "Correlate findings with common vulnerability patterns and exploitation techniques."
        ),
    )
    
    # Web Search for Known Vulnerabilities
    known_vulnerability_search_agent = Agent(
        name="Known Vulnerability Researcher",
        handoff_description="Searches for known CVEs, exploits, and vulnerability research",
        instructions=(
            "Perform comprehensive web searches for known vulnerabilities, CVEs, and security research. "
            "Search for similar binaries, vulnerability patterns, and existing exploits. "
            "Focus on recent disclosures and provide context about exploit availability."
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    

    
    # --- Main Orchestrator Agent ---
    super_agent = Agent(
        name="Super Vulnerability Research Agent",
        instructions=(
            "You are an elite vulnerability research agent that combines multiple specialized capabilities:\n\n"
            "1. **Binary Analysis**: Use Ghidra for deep reverse engineering analysis\n"
            "2. **Vulnerability Research**: Search for known CVEs and similar vulnerabilities\n" 
            "3. **Reasoning & Assessment**: Analyze potential zero-day opportunities\n\n"
            "**Workflow for comprehensive analysis:**\n"
            "1. First, hand off to Ghidra Binary Analyst for technical reverse engineering\n"
            "2. Then, hand off to Vulnerability Reasoning Expert for pattern analysis\n"
            "3. Next, hand off to Known Vulnerability Researcher for CVE research\n"
            "4. Finally, synthesize all findings into a comprehensive vulnerability assessment\n\n"
            "**Output Format:**\n"
            "- Executive Summary of findings\n"
            "- Technical Analysis (functions, addresses, code patterns)\n"
            "- Vulnerability Assessment (potential zero-days vs known issues)\n"
            "- Risk Rating and Exploitation Difficulty\n"
            "- Recommendations for further research\n\n"
            "Be thorough, technical, and provide actionable intelligence for security researchers."
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
    
    # Example queries - uncomment the one you want to run
    queries = [
        # Comprehensive binary analysis
        "Please perform a comprehensive vulnerability analysis of the binary file in Ghidra. Identify the most vulnerable functions for potential zero-day exploitation, search for known CVEs affecting similar binaries, and provide a complete risk assessment.",
        
        # macOS specific research
        # "Analyze macOS system binaries for privilege escalation vulnerabilities. Focus on recent CVEs and potential zero-day opportunities in system services.",
        
        # Custom query
        # "Research kernel vulnerabilities in macOS Sequoia, analyze any available binaries using Ghidra, and identify exploitation techniques for local privilege escalation."
    ]
    
    # Run analysis with the first query
    await run_super_analysis(queries[0])


if __name__ == "__main__":
    print("🚀 Initializing Super Vulnerability Research Agent...")
    print("🔧 This agent combines:")
    print("   • Ghidra reverse engineering analysis")
    print("   • Web-based vulnerability research") 
    print("   • Advanced reasoning and synthesis")
    print("\n" + "=" * 50)
    
    asyncio.run(main())