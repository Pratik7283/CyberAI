"""
Adaptive Router for CyberSentinel Lite.

This module implements the Adaptive RAG concept:
- If input is simple/known → answer directly via LLM
- If input is complex/unknown → trigger full RAG pipeline
- Uses Groq Llama models with structured output (Pydantic) to classify
"""

import os
from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

from schemas.models import RouteDecision

# Load environment variables
load_dotenv()


class AdaptiveRouter:
    """
    Adaptive router that classifies queries and determines the routing strategy.
    """
    
    def __init__(self, model_name: str = "openai/gpt-oss-20b"):
        """
        Initialize the adaptive router.
        
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
        self.structured_llm = self.llm.with_structured_output(RouteDecision)
        
        # Define the routing prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity query classifier for a threat analysis system.
Your task is to analyze user queries and determine:
1. The ROUTE: whether to answer directly or use full RAG pipeline
2. The QUERY TYPE: what kind of threat information is being requested
3. The REASON: explain your decision

Routes:
- "direct_llm": Use for simple, general questions about cybersecurity concepts that don't require real-time data
  Examples: "What is ransomware?", "How does phishing work?", "Explain zero-day vulnerabilities"
- "full_rag": Use for specific threat investigations requiring real-time API data
  Examples: Specific IP addresses, CVE IDs, recent threat keywords, specific malware names

Query Types:
- "ip": The query contains an IP address
- "cve": The query contains a CVE ID (format: CVE-YYYY-NNNN)
- "keyword": The query is a general threat keyword or topic

Be precise and accurate in your classification."""),
            ("human", "Query: {query}")
        ])
        
        # Create the chain
        self.chain = self.prompt | self.structured_llm
    
    def route_query(self, query: str) -> Dict[str, Any]:
        """
        Classify and route a user query.
        
        Args:
            query: User input query
            
        Returns:
            Dictionary containing route decision and metadata
        """
        try:
            # Invoke the chain
            decision = self.chain.invoke({"query": query})
            
            # Convert to dictionary
            result = {
                "route": decision.route,
                "reason": decision.reason,
                "query_type": decision.query_type,
                "original_query": query
            }
            
            return result
            
        except Exception as e:
            # Fallback to full_rag if classification fails
            print(f"Error in adaptive routing: {e}")
            return {
                "route": "full_rag",
                "reason": "Classification failed, defaulting to full RAG pipeline",
                "query_type": "keyword",
                "original_query": query
            }
    
    def should_use_rag(self, query: str) -> bool:
        """
        Simple boolean check if query should use RAG.
        
        Args:
            query: User input query
            
        Returns:
            True if should use RAG, False otherwise
        """
        decision = self.route_query(query)
        return decision["route"] == "full_rag"
    
    def get_query_type(self, query: str) -> str:
        """
        Get the query type classification.
        
        Args:
            query: User input query
            
        Returns:
            Query type: 'ip', 'cve', or 'keyword'
        """
        decision = self.route_query(query)
        return decision["query_type"]


# Singleton instance
_adaptive_router_instance: AdaptiveRouter = None


def get_adaptive_router() -> AdaptiveRouter:
    """
    Get the singleton instance of the adaptive router.
    
    Returns:
        AdaptiveRouter instance
    """
    global _adaptive_router_instance
    if _adaptive_router_instance is None:
        _adaptive_router_instance = AdaptiveRouter()
    return _adaptive_router_instance
