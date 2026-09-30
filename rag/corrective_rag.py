"""
Corrective RAG for CyberSentinel Lite.

This module implements the Corrective RAG concept:
- After retrieval, grade each document/result
- "relevant" → keep and proceed
- "irrelevant" or "stale" → discard and re-fetch
- Uses Groq Llama models with structured Pydantic output to grade
- If all results irrelevant → fallback to NewsAPI web search
"""

import os
from typing import List, Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

from schemas.models import DocumentGrade

# Load environment variables
load_dotenv()


class CorrectiveRAG:
    """
    Corrective RAG grader that evaluates retrieved documents for relevance.
    """
    
    def __init__(self, model_name: str = "openai/gpt-oss-20b"):
        """
        Initialize the corrective RAG grader.
        
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
        self.structured_llm = self.llm.with_structured_output(DocumentGrade)
        
        # Define the grading prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a document relevance grader for a cybersecurity threat analysis system.
Your task is to evaluate whether retrieved documents are relevant to the user's query.

Grading Criteria:
- "relevant": The document contains information directly related to the query and provides useful threat intelligence
- "irrelevant": The document is not related to the query or does not contain useful information
- "stale": The document is outdated (older than 6 months) and may not reflect current threat landscape

Consider the following when grading:
1. Does the document address the specific threat mentioned in the query?
2. Is the information recent enough to be actionable?
3. Does it provide actionable intelligence (IOCs, CVEs, mitigation steps)?
4. Is the source credible and the information accurate?

Be strict in your grading to ensure high-quality results."""),
            ("human", """Query: {query}

Document to evaluate:
{document}

Grade this document as 'relevant', 'irrelevant', or 'stale' and explain your reasoning.""")
        ])
        
        # Create the chain
        self.chain = self.prompt | self.structured_llm
    
    def grade_document(self, query: str, document: str) -> Dict[str, Any]:
        """
        Grade a single document for relevance to the query.
        
        Args:
            query: User's original query
            document: Document content to grade
            
        Returns:
            Dictionary containing grade and reasoning
        """
        try:
            # Invoke the chain
            grade = self.chain.invoke({
                "query": query,
                "document": document
            })
            
            # Convert to dictionary
            result = {
                "score": grade.score,
                "reason": grade.reason
            }
            
            return result
            
        except Exception as e:
            # Fallback to irrelevant if grading fails
            print(f"Error grading document: {e}")
            return {
                "score": "irrelevant",
                "reason": f"Grading failed: {str(e)}"
            }
    
    def grade_documents(self, query: str, documents: List[str]) -> Dict[str, Any]:
        """
        Grade multiple documents and filter for relevant ones.
        
        Args:
            query: User's original query
            documents: List of document contents to grade
            
        Returns:
            Dictionary containing:
            - relevant_docs: List of documents graded as relevant
            - irrelevant_docs: List of documents graded as irrelevant
            - stale_docs: List of documents graded as stale
            - overall_grade: 'relevant' if any relevant docs, else 'irrelevant'
        """
        relevant_docs = []
        irrelevant_docs = []
        stale_docs = []
        
        for doc in documents:
            grade_result = self.grade_document(query, doc)
            
            if grade_result["score"] == "relevant":
                relevant_docs.append({
                    "content": doc,
                    "reason": grade_result["reason"]
                })
            elif grade_result["score"] == "stale":
                stale_docs.append({
                    "content": doc,
                    "reason": grade_result["reason"]
                })
            else:
                irrelevant_docs.append({
                    "content": doc,
                    "reason": grade_result["reason"]
                })
        
        # Determine overall grade
        overall_grade = "relevant" if relevant_docs else "irrelevant"
        
        return {
            "relevant_docs": relevant_docs,
            "irrelevant_docs": irrelevant_docs,
            "stale_docs": stale_docs,
            "overall_grade": overall_grade,
            "total_docs": len(documents),
            "relevant_count": len(relevant_docs)
        }
    
    def should_fallback(self, query: str, documents: List[str]) -> bool:
        """
        Determine if we should fallback to alternative search.
        
        Args:
            query: User's original query
            documents: List of document contents to grade
            
        Returns:
            True if should fallback, False otherwise
        """
        result = self.grade_documents(query, documents)
        return result["overall_grade"] == "irrelevant"
    
    def get_relevant_documents(self, query: str, documents: List[str]) -> List[str]:
        """
        Get only the relevant documents from a list.
        
        Args:
            query: User's original query
            documents: List of document contents to grade
            
        Returns:
            List of relevant document contents
        """
        result = self.grade_documents(query, documents)
        return [doc["content"] for doc in result["relevant_docs"]]


# Singleton instance
_corrective_rag_instance: CorrectiveRAG = None


def get_corrective_rag() -> CorrectiveRAG:
    """
    Get the singleton instance of the corrective RAG grader.
    
    Returns:
        CorrectiveRAG instance
    """
    global _corrective_rag_instance
    if _corrective_rag_instance is None:
        _corrective_rag_instance = CorrectiveRAG()
    return _corrective_rag_instance
