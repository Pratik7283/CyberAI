"""
Responder Agent for CyberSentinel Lite.

This module generates structured incident reports based on investigation results.
Uses Groq Llama models with structured Pydantic output (IncidentReport model).
"""

import os
import json
from typing import Dict, Any
from datetime import datetime
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

from schemas.models import IncidentReport

# Load environment variables
load_dotenv()


class ResponderAgent:
    """
    Responder agent that generates structured threat reports.
    """
    
    def __init__(self, model_name: str = "openai/gpt-oss-20b"):
        """
        Initialize the responder agent.
        
        Args:
            model_name: Name of the Groq model to use
        """
        self.model_name = model_name
        self.llm = ChatGroq(
            model=model_name,
            temperature=0,
            api_key=os.getenv("GROQ_API_KEY")
        )
        
        # Create structured LLM with Pydantic model
        self.structured_llm = self.llm.with_structured_output(IncidentReport)
        
        # Define the report generation prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity threat analyst responsible for generating incident reports.
Your task is to analyze investigation results and create a structured threat report.

Report Requirements:
1. threat_id: Unique identifier (use CVE ID, IP address, or generate a descriptive ID)
2. timestamp: Current ISO timestamp
3. query: Original user query
4. threat_type: One of 'malicious_ip', 'vulnerability', or 'news_threat'
5. severity: One of 'low', 'medium', 'high', or 'critical' (based on CVSS score, abuse confidence, or threat impact)
6. summary: Concise 2-3 sentence summary of the threat
7. affected_systems: List of affected software, systems, or platforms
8. cve_references: List of related CVE IDs (if any)
9. indicators: List of IOCs (IPs, hashes, domains, etc.)
10. mitigation_steps: List of 3-5 actionable mitigation steps
11. confidence_score: Float from 0.0 to 1.0 based on data quality and source reliability
12. source_used: Which API/tool provided the primary data

Severity Guidelines:
- Critical: CVSS 9.0-10.0, abuse confidence >= 75%, or widespread active exploitation
- High: CVSS 7.0-8.9, abuse confidence 50-74%, or significant impact
- Medium: CVSS 4.0-6.9, abuse confidence 25-49%, or moderate impact
- Low: CVSS 0.1-3.9, abuse confidence < 25%, or minimal impact

Be accurate, concise, and provide actionable intelligence."""),
            ("human", """Original Query: {query}
Query Type: {query_type}

Investigation Results:
{investigation_data}

Past Incidents (if any):
{past_incidents}

Generate a comprehensive incident report based on this information.""")
        ])
        
        # Create the chain
        self.chain = self.prompt | self.structured_llm
    
    def generate_report(self, query: str, query_type: str, investigation_data: Dict[str, Any], past_incidents: list = None) -> Dict[str, Any]:
        """
        Generate a structured incident report.
        
        Args:
            query: Original user query
            query_type: Type of query ('ip', 'cve', or 'keyword')
            investigation_data: Data from the investigator agent
            past_incidents: Similar past incidents from ChromaDB
            
        Returns:
            Dictionary containing the incident report
        """
        try:
            # Format investigation data for the prompt
            investigation_text = json.dumps(investigation_data, indent=2)
            
            # Format past incidents
            past_incidents_text = json.dumps(past_incidents, indent=2) if past_incidents else "None"
            
            # Invoke the chain
            report = self.chain.invoke({
                "query": query,
                "query_type": query_type,
                "investigation_data": investigation_text,
                "past_incidents": past_incidents_text
            })
            
            # Convert to dictionary
            result = {
                "threat_id": report.threat_id,
                "timestamp": report.timestamp,
                "query": report.query,
                "threat_type": report.threat_type,
                "severity": report.severity,
                "summary": report.summary,
                "affected_systems": report.affected_systems,
                "cve_references": report.cve_references,
                "indicators": report.indicators,
                "mitigation_steps": report.mitigation_steps,
                "confidence_score": report.confidence_score,
                "source_used": report.source_used
            }
            
            return result
            
        except Exception as e:
            print(f"Error generating report: {e}")
            # Fallback to basic report
            return self._generate_fallback_report(query, query_type, investigation_data, str(e))
    
    def _generate_fallback_report(self, query: str, query_type: str, investigation_data: Dict[str, Any], error: str) -> Dict[str, Any]:
        """
        Generate a fallback report if structured generation fails.
        
        Args:
            query: Original user query
            query_type: Type of query
            investigation_data: Data from investigator
            error: Error message
            
        Returns:
            Basic incident report dictionary
        """
        # Extract basic information from investigation data
        tool_calls = investigation_data.get("tool_calls", [])
        source_used = "unknown"
        
        if tool_calls:
            source_used = tool_calls[0].get("tool", "unknown")
        
        # Determine threat type based on query_type
        threat_type_map = {
            "ip": "malicious_ip",
            "cve": "vulnerability",
            "keyword": "news_threat"
        }
        threat_type = threat_type_map.get(query_type, "news_threat")
        
        # Generate threat ID
        if query_type == "cve":
            threat_id = query.upper()
        elif query_type == "ip":
            threat_id = query
        else:
            threat_id = f"THREAT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        return {
            "threat_id": threat_id,
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "threat_type": threat_type,
            "severity": "medium",
            "summary": f"Report generation encountered an error: {error}. Basic information retrieved from {source_used}.",
            "affected_systems": [],
            "cve_references": [],
            "indicators": [],
            "mitigation_steps": [
                "Review the investigation data for more details",
                "Contact security team for manual analysis",
                "Check official sources for updated information"
            ],
            "confidence_score": 0.5,
            "source_used": source_used,
            "error": error
        }
    
    def generate_direct_answer(self, query: str) -> Dict[str, Any]:
        """
        Generate a direct answer for simple queries (without full RAG).
        
        Args:
            query: User's query
            
        Returns:
            Simple answer dictionary
        """
        try:
            # Use LLM directly for simple questions
            prompt = ChatPromptTemplate.from_messages([
                ("system", """You are a cybersecurity educator.
Provide clear, accurate, and concise answers to cybersecurity questions.
Keep responses under 200 words and focus on practical understanding."""),
                ("human", "{query}")
            ])
            
            chain = prompt | self.llm
            response = chain.invoke({"query": query})
            
            return {
                "type": "direct_answer",
                "query": query,
                "answer": response.content,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error generating direct answer: {e}")
            return {
                "type": "direct_answer",
                "query": query,
                "answer": f"Error generating answer: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }


# Singleton instance
_responder_agent_instance: ResponderAgent = None


def get_responder_agent() -> ResponderAgent:
    """
    Get the singleton instance of the responder agent.
    
    Returns:
        ResponderAgent instance
    """
    global _responder_agent_instance
    if _responder_agent_instance is None:
        _responder_agent_instance = ResponderAgent()
    return _responder_agent_instance
