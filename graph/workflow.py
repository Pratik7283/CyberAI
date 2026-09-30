"""
LangGraph Workflow for CyberSentinel Lite.

This module implements the complete agent workflow using LangGraph StateGraph:
- Nodes: adaptive_router, investigator, grader, fallback_search, responder
- Edges: router → investigator OR direct_answer, investigator → grader, 
         grader → responder OR fallback_search, fallback_search → grader, responder → END
"""

import os
from typing import TypedDict, Annotated, Literal
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from dotenv import load_dotenv

from schemas.models import CyberState
from rag.adaptive_router import get_adaptive_router
from rag.corrective_rag import get_corrective_rag
from agents.investigator import get_investigator_agent
from agents.responder import get_responder_agent
from tools.news_tool import get_news_tool
from memory.vector_store import get_vector_store

# Load environment variables
load_dotenv()


# Define the state schema (using the one from schemas/models.py)
class CyberState(TypedDict):
    query: str
    query_type: str
    route: str
    retrieved_data: list[str]
    retrieval_grade: str
    past_incidents: list[str]
    final_report: dict
    messages: Annotated[list, add_messages]
    fallback_count: int
    source_from_cache: bool


class CyberSentinelWorkflow:
    """
    Main workflow orchestration for CyberSentinel Lite using LangGraph.
    """
    
    def __init__(self):
        """
        Initialize the workflow with all necessary components.
        """
        # Initialize components
        self.adaptive_router = get_adaptive_router()
        self.corrective_rag = get_corrective_rag()
        self.investigator = get_investigator_agent()
        self.responder = get_responder_agent()
        self.news_tool = get_news_tool()
        self.vector_store = get_vector_store()
        
        # Build the workflow graph
        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> StateGraph:
        """
        Build the LangGraph workflow with nodes and edges.
        
        Returns:
            Compiled StateGraph
        """
        # Create the graph
        workflow = StateGraph(CyberState)
        
        # Add nodes
        workflow.add_node("adaptive_router", self._adaptive_router_node)
        workflow.add_node("investigator", self._investigator_node)
        workflow.add_node("grader", self._grader_node)
        workflow.add_node("fallback_search", self._fallback_search_node)
        workflow.add_node("responder", self._responder_node)
        workflow.add_node("direct_answer", self._direct_answer_node)
        
        # Set entry point
        workflow.set_entry_point("adaptive_router")
        
        # Add edges
        # Router → investigator OR direct_answer
        workflow.add_conditional_edges(
            "adaptive_router",
            self._route_decision,
            {
                "full_rag": "investigator",
                "direct_llm": "direct_answer"
            }
        )
        
        # Investigator → grader
        workflow.add_edge("investigator", "grader")
        
        # Grader → responder OR fallback_search
        workflow.add_conditional_edges(
            "grader",
            self._grade_decision,
            {
                "relevant": "responder",
                "irrelevant": "fallback_search"
            }
        )
        
        # Fallback search → grader (re-grade)
        workflow.add_edge("fallback_search", "grader")
        
        # Responder → END
        workflow.add_edge("responder", END)
        
        # Direct answer → END
        workflow.add_edge("direct_answer", END)
        
        # Compile the workflow
        return workflow.compile()
    
    def _adaptive_router_node(self, state: CyberState) -> CyberState:
        """
        Adaptive router node: Classifies query and determines route.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("🔀 [Adaptive Router] Classifying query...")
        
        query = state["query"]
        
        # Get route decision
        decision = self.adaptive_router.route_query(query)
        
        # Update state
        state["route"] = decision["route"]
        state["query_type"] = decision["query_type"]
        
        print(f"   Route: {decision['route']}")
        print(f"   Query Type: {decision['query_type']}")
        print(f"   Reason: {decision['reason']}")
        
        return state
    
    def _investigator_node(self, state: CyberState) -> CyberState:
        """
        Investigator node: Agentic RAG tool selection and execution.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("🔍 [Investigator] Gathering threat intelligence...")
        
        query = state["query"]
        query_type = state["query_type"]
        
        # Run investigation
        investigation = self.investigator.investigate_direct(query, query_type)
        
        # Update state
        state["retrieved_data"] = investigation.get("raw_data", [])
        state["past_incidents"] = investigation.get("past_incidents", [])
        state["source_from_cache"] = investigation.get("source_from_cache", False)
        
        print(f"   Retrieved {len(state['retrieved_data'])} data sources")
        print(f"   Found {len(state['past_incidents'])} similar past incidents")
        if state.get("source_from_cache"):
            print(f"   ✓ Using cached data from vector store")
        
        return state
    
    def _grader_node(self, state: CyberState) -> CyberState:
        """
        Grader node: Corrective RAG document grading.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("📊 [Grader] Evaluating document relevance...")
        
        query = state["query"]
        retrieved_data = state["retrieved_data"]
        
        # Grade documents
        grade_result = self.corrective_rag.grade_documents(query, retrieved_data)
        
        # Update state
        state["retrieval_grade"] = grade_result["overall_grade"]
        state["retrieved_data"] = [
            doc["content"] for doc in grade_result["relevant_docs"]
        ]
        
        print(f"   Overall Grade: {grade_result['overall_grade']}")
        print(f"   Relevant Documents: {grade_result['relevant_count']}/{grade_result['total_docs']}")
        
        # Force proceed to responder if max fallback attempts reached
        fallback_count = state.get("fallback_count", 0)
        if fallback_count >= 2 and grade_result["overall_grade"] == "irrelevant":
            print(f"   Max fallback attempts reached, proceeding with available data")
            state["retrieval_grade"] = "relevant"
        
        return state
    
    def _fallback_search_node(self, state: CyberState) -> CyberState:
        """
        Fallback search node: Searches NewsAPI when retrieval is irrelevant.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("🔄 [Fallback Search] Using NewsAPI as fallback...")
        
        query = state["query"]
        
        # Search for news
        news_results = self.news_tool.search_cybersecurity_news(query, page_size=5)
        
        # Convert to string format
        news_data = [str(article) for article in news_results]
        
        # Update state
        state["retrieved_data"] = news_data
        state["fallback_count"] = state.get("fallback_count", 0) + 1
        
        print(f"   Retrieved {len(news_data)} news articles")
        print(f"   Fallback attempt #{state['fallback_count']}")
        
        return state
    
    def _responder_node(self, state: CyberState) -> CyberState:
        """
        Responder node: Generates structured incident report.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("📝 [Responder] Generating incident report...")
        
        query = state["query"]
        query_type = state["query_type"]
        retrieved_data = state["retrieved_data"]
        past_incidents = state["past_incidents"]
        source_from_cache = state.get("source_from_cache", False)
        
        # Prepare investigation data
        investigation_data = {
            "retrieved_data": retrieved_data,
            "source": "vector_store" if source_from_cache else "agentic_rag_pipeline"
        }
        
        # Generate report
        report = self.responder.generate_report(
            query=query,
            query_type=query_type,
            investigation_data=investigation_data,
            past_incidents=past_incidents
        )
        
        # Override source if from cache
        if source_from_cache:
            report["source_used"] = "past_threats (vector_store)"
        
        # Update state
        state["final_report"] = report
        
        print(f"   Report generated for: {report.get('threat_id', 'unknown')}")
        print(f"   Severity: {report.get('severity', 'unknown')}")
        print(f"   Confidence: {report.get('confidence_score', 0.0)}")
        
        # Store report in vector store (only if not from cache to avoid duplicates)
        if not source_from_cache:
            try:
                self.vector_store.add_report(report, query)
                print("   Report stored in vector database")
            except Exception as e:
                print(f"   Warning: Could not store report in vector store: {e}")
        else:
            print("   Skipping storage (data from cache)")
        
        return state
    
    def _direct_answer_node(self, state: CyberState) -> CyberState:
        """
        Direct answer node: Answers simple queries without full RAG.
        
        Args:
            state: Current workflow state
            
        Returns:
            Updated state
        """
        print("💬 [Direct Answer] Generating simple response...")
        
        query = state["query"]
        
        # Generate direct answer
        answer = self.responder.generate_direct_answer(query)
        
        # Update state with answer as a report-like structure
        state["final_report"] = {
            "type": "direct_answer",
            "threat_id": "N/A",
            "timestamp": answer.get("timestamp", ""),
            "query": query,
            "threat_type": "general",
            "severity": "N/A",
            "summary": answer.get("answer", ""),
            "affected_systems": [],
            "cve_references": [],
            "indicators": [],
            "mitigation_steps": [],
            "confidence_score": 0.8,
            "source_used": "direct_llm"
        }
        
        print("   Direct answer generated")
        
        return state
    
    def _route_decision(self, state: CyberState) -> str:
        """
        Conditional edge function for adaptive router.
        
        Args:
            state: Current workflow state
            
        Returns:
            Next node name
        """
        return state["route"]
    
    def _grade_decision(self, state: CyberState) -> str:
        """
        Conditional edge function for grader.
        
        Args:
            state: Current workflow state
            
        Returns:
            Next node name
        """
        return state["retrieval_grade"]
    
    def run(self, query: str) -> dict:
        """
        Run the complete workflow for a query.
        
        Args:
            query: User's input query
            
        Returns:
            Final workflow state with report
        """
        print(f"\n{'='*60}")
        print(f"🛡️ CyberSentinel Lite - Starting Analysis")
        print(f"{'='*60}")
        print(f"Query: {query}\n")
        
        # Initialize state
        initial_state: CyberState = {
            "query": query,
            "query_type": "",
            "route": "",
            "retrieved_data": [],
            "retrieval_grade": "",
            "past_incidents": [],
            "final_report": {},
            "messages": [],
            "fallback_count": 0,
            "source_from_cache": False
        }
        
        # Run the workflow
        try:
            final_state = self.workflow.invoke(initial_state)
            
            print(f"\n{'='*60}")
            print(f"✅ Analysis Complete")
            print(f"{'='*60}\n")
            
            return final_state
            
        except Exception as e:
            print(f"\n❌ Error in workflow: {e}\n")
            return {
                **initial_state,
                "final_report": {
                    "error": str(e),
                    "query": query
                }
            }
    
    def stream(self, query: str):
        """
        Stream the workflow execution for real-time updates.
        
        Args:
            query: User's input query
            
        Yields:
            Workflow state updates
        """
        print(f"\n{'='*60}")
        print(f"🛡️ CyberSentinel Lite - Starting Analysis")
        print(f"{'='*60}")
        print(f"Query: {query}\n")
        
        # Initialize state
        initial_state: CyberState = {
            "query": query,
            "query_type": "",
            "route": "",
            "retrieved_data": [],
            "retrieval_grade": "",
            "past_incidents": [],
            "final_report": {},
            "messages": [],
            "fallback_count": 0,
            "source_from_cache": False
        }
        
        # Stream the workflow
        try:
            for event in self.workflow.stream(initial_state):
                yield event
        except Exception as e:
            print(f"\n❌ Error in workflow: {e}\n")
            yield {"error": str(e)}


# Singleton instance
_workflow_instance: CyberSentinelWorkflow = None


def get_workflow() -> CyberSentinelWorkflow:
    """
    Get the singleton instance of the workflow.
    
    Returns:
        CyberSentinelWorkflow instance
    """
    global _workflow_instance
    if _workflow_instance is None:
        _workflow_instance = CyberSentinelWorkflow()
    return _workflow_instance
