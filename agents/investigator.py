"""
Investigator Agent for CyberSentinel Lite.

This module implements the Agentic RAG concept:
- Agent autonomously DECIDES which tool to call
- NVD API (if input looks like a CVE ID)
- AbuseIPDB API (if input is an IP address)
- NewsAPI (if input is a keyword/topic)
- ChromaDB (always check local memory first)
- Uses LangChain tool calling for this
"""

import os
import json
from typing import Dict, Any, List
from langchain_groq import ChatGroq
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from dotenv import load_dotenv

from tools.nvd_tool import get_nvd_tool
from tools.abuseipdb_tool import get_abuseipdb_tool
from tools.news_tool import get_news_tool
from memory.vector_store import get_vector_store

# Load environment variables
load_dotenv()


class InvestigatorAgent:
    """
    Investigator agent that autonomously selects and calls appropriate tools.
    """
    
    def __init__(self, model_name: str = "openai/gpt-oss-20b"):
        """
        Initialize the investigator agent.
        
        Args:
            model_name: Name of the Groq model to use
        """
        self.model_name = model_name
        self.llm = ChatGroq(
            model=model_name,
            temperature=0,
            api_key=os.getenv("GROQ_API_KEY")
        )
        
        # Initialize tools
        self.nvd_tool = get_nvd_tool()
        self.abuseipdb_tool = get_abuseipdb_tool()
        self.news_tool = get_news_tool()
        self.vector_store = get_vector_store()
        
        # Define tools for LangChain
        self.tools = [
            self._create_nvd_tool(),
            self._create_abuseipdb_tool(),
            self._create_news_tool(),
            self._create_vector_search_tool()
        ]
        
        # Bind tools to LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)
    
    def _create_nvd_tool(self):
        """
        Create LangChain tool for NVD API.
        """
        @tool
        def lookup_cve(cve_id: str) -> str:
            """
            Look up a specific CVE (Common Vulnerabilities and Exposures) by ID.
            Use this when the query contains a CVE ID (format: CVE-YYYY-NNNN).
            Returns detailed vulnerability information including CVSS score, severity, and affected systems.
            """
            try:
                result = self.nvd_tool.lookup_cve(cve_id)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        return lookup_cve
    
    def _create_abuseipdb_tool(self):
        """
        Create LangChain tool for AbuseIPDB API.
        """
        @tool
        def check_ip_reputation(ip_address: str) -> str:
            """
            Check the reputation of an IP address using AbuseIPDB.
            Use this when the query contains an IP address (IPv4 format: X.X.X.X).
            Returns abuse confidence score, severity, country, ISP, and recent reports.
            """
            try:
                result = self.abuseipdb_tool.check_ip(ip_address)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        return check_ip_reputation
    
    def _create_news_tool(self):
        """
        Create LangChain tool for NewsAPI.
        """
        @tool
        def search_threat_news(keyword: str) -> str:
            """
            Search for cybersecurity threat news articles.
            Use this for general threat keywords or topics (e.g., "ransomware", "phishing", "zero-day").
            Returns recent news articles related to the threat.
            """
            try:
                results = self.news_tool.search_cybersecurity_news(keyword, page_size=5)
                return json.dumps(results, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        return search_threat_news
    
    def _create_vector_search_tool(self):
        """
        Create LangChain tool for ChromaDB vector search.
        """
        @tool
        def search_past_incidents(query: str) -> str:
            """
            Search for similar past threat incidents in the local vector database.
            Always use this tool first to check if we have analyzed similar threats before.
            Returns similar past incidents with their details.
            """
            try:
                results = self.vector_store.search_similar_incidents(query, n_results=3)
                return json.dumps(results, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        return search_past_incidents
    
    def investigate(self, query: str, query_type: str) -> Dict[str, Any]:
        """
        Investigate a threat query by autonomously selecting and calling appropriate tools.
        
        Args:
            query: User's input query
            query_type: Type of query ('ip', 'cve', or 'keyword')
            
        Returns:
            Dictionary containing investigation results
        """
        try:
            # First, always check vector store for past incidents
            past_incidents = self.vector_store.search_similar_incidents(query, n_results=3)
            
            # Prepare the system message for the agent
            system_message = SystemMessage(content="""You are a cybersecurity investigator agent.
Your task is to analyze threat queries and use the appropriate tools to gather information.

Tool Selection Guidelines:
1. ALWAYS start by searching past incidents using search_past_incidents
2. If query contains a CVE ID (format: CVE-YYYY-NNNN), use lookup_cve
3. If query contains an IP address (IPv4 format), use check_ip_reputation
4. If query is a general keyword/topic, use search_threat_news

Be thorough and gather as much relevant information as possible.
Return all findings in a structured format.""")
            
            # Prepare the human message
            human_message = HumanMessage(content=f"""
Query: {query}
Query Type: {query_type}

Investigate this threat and gather relevant information using the available tools.""")
            
            # Invoke the LLM with tools
            response = self.llm_with_tools.invoke([system_message, human_message])
            
            # Extract tool calls if any
            tool_calls = response.tool_calls if hasattr(response, 'tool_calls') else []
            
            # Execute tool calls
            tool_results = []
            for tool_call in tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                
                # Find and execute the tool
                for tool in self.tools:
                    if tool.name == tool_name:
                        result = tool.invoke(tool_args)
                        tool_results.append({
                            "tool": tool_name,
                            "args": tool_args,
                            "result": result
                        })
                        break
            
            # If no tools were called, use the response content directly
            if not tool_results:
                tool_results.append({
                    "tool": "direct_llm",
                    "args": {},
                    "result": response.content
                })
            
            return {
                "query": query,
                "query_type": query_type,
                "past_incidents": past_incidents,
                "tool_calls": tool_results,
                "raw_data": [json.dumps(tr, indent=2) for tr in tool_results]
            }
            
        except Exception as e:
            print(f"Error in investigation: {e}")
            return {
                "query": query,
                "query_type": query_type,
                "error": str(e),
                "past_incidents": [],
                "tool_calls": [],
                "raw_data": []
            }
    
    def investigate_direct(self, query: str, query_type: str) -> Dict[str, Any]:
        """
        Direct investigation without LLM tool calling (simpler approach).
        
        Args:
            query: User's input query
            query_type: Type of query ('ip', 'cve', or 'keyword')
            
        Returns:
            Dictionary containing investigation results
        """
        try:
            # Always check vector store first
            past_incidents = self.vector_store.search_similar_incidents(query, n_results=3)
            
            tool_results = []
            source_from_cache = False
            
            # If we have relevant past incidents, use them as primary source
            if past_incidents and len(past_incidents) > 0:
                # Check if any past incident contains the exact query (CVE ID or IP)
                query_lower = query.lower()
                for incident in past_incidents:
                    incident_lower = incident.lower()
                    # For CVE: exact match or contains CVE ID
                    if query_type == "cve" and ("cve" in incident_lower and any(c in incident_lower for c in query_lower.split())):
                        source_from_cache = True
                        break
                    # For IP: exact match
                    elif query_type == "ip" and query in incident:
                        source_from_cache = True
                        break
                    # For keyword: semantic similarity (already handled by vector search)
                    elif query_type == "keyword":
                        source_from_cache = True
                        break
            
            if source_from_cache:
                # Use past incident data instead of calling API
                tool_results.append({
                    "tool": "vector_store",
                    "args": {"query": query},
                    "result": past_incidents[0] if past_incidents else "No past incidents found"
                })
                return {
                    "query": query,
                    "query_type": query_type,
                    "past_incidents": past_incidents,
                    "tool_calls": tool_results,
                    "raw_data": [json.dumps(tr, indent=2) for tr in tool_results],
                    "source_from_cache": True
                }
            
            # Select tool based on query type
            if query_type == "cve":
                # Extract CVE ID and look up
                cve_id = self.nvd_tool.extract_cve_id(query)
                if cve_id:
                    result = self.nvd_tool.lookup_cve(cve_id)
                    tool_results.append({
                        "tool": "nvd_lookup",
                        "args": {"cve_id": cve_id},
                        "result": result
                    })
            
            elif query_type == "ip":
                # Extract IP and check reputation
                ip_address = self.abuseipdb_tool.extract_ip_address(query)
                if ip_address:
                    result = self.abuseipdb_tool.check_ip(ip_address)
                    tool_results.append({
                        "tool": "abuseipdb_check",
                        "args": {"ip_address": ip_address},
                        "result": result
                    })
            
            else:  # keyword
                # Search for threat news
                result = self.news_tool.search_cybersecurity_news(query, page_size=5)
                tool_results.append({
                    "tool": "news_search",
                    "args": {"keyword": query},
                    "result": result
                })
            
            return {
                "query": query,
                "query_type": query_type,
                "past_incidents": past_incidents,
                "tool_calls": tool_results,
                "raw_data": [json.dumps(tr, indent=2) for tr in tool_results],
                "source_from_cache": False
            }
            
        except Exception as e:
            print(f"Error in direct investigation: {e}")
            return {
                "query": query,
                "query_type": query_type,
                "error": str(e),
                "past_incidents": [],
                "tool_calls": [],
                "raw_data": []
            }


# Singleton instance
_investigator_agent_instance: InvestigatorAgent = None


def get_investigator_agent() -> InvestigatorAgent:
    """
    Get the singleton instance of the investigator agent.
    
    Returns:
        InvestigatorAgent instance
    """
    global _investigator_agent_instance
    if _investigator_agent_instance is None:
        _investigator_agent_instance = InvestigatorAgent()
    return _investigator_agent_instance
