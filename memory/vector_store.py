"""
ChromaDB Vector Store for CyberSentinel Lite.

This module handles:
- ChromaDB collection initialization
- Storing threat reports as embeddings
- Retrieving similar past incidents
- Managing the vector memory for the RAG pipeline
"""

import os
from typing import List, Optional
from datetime import datetime
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions


class VectorStore:
    """
    Manages ChromaDB operations for storing and retrieving threat reports.
    """
    
    def __init__(self, collection_name: str = "cybersentinel_reports", persist_directory: str = "./chroma_db"):
        """
        Initialize the vector store.
        
        Args:
            collection_name: Name of the ChromaDB collection
            persist_directory: Directory to persist the database
        """
        self.collection_name = collection_name
        self.persist_directory = persist_directory
        
        # Create persist directory if it doesn't exist
        os.makedirs(persist_directory, exist_ok=True)
        
        # Initialize ChromaDB client with persistence
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Initialize embedding function (using default all-MiniLM-L6-v2)
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.embedding_function
        )
    
    def add_report(self, report: dict, query: str) -> str:
        """
        Add a threat report to the vector store.
        
        Args:
            report: Incident report dictionary
            query: Original query that generated the report
            
        Returns:
            Document ID of the added report
        """
        try:
            # Generate a unique ID based on timestamp and threat_id
            doc_id = f"{report.get('threat_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create a searchable text from the report
            searchable_text = self._create_searchable_text(report, query)
            
            # Add to collection
            self.collection.add(
                documents=[searchable_text],
                metadatas=[{
                    "threat_id": report.get("threat_id", ""),
                    "threat_type": report.get("threat_type", ""),
                    "severity": report.get("severity", ""),
                    "timestamp": report.get("timestamp", ""),
                    "query": query,
                    "source": report.get("source_used", "")
                }],
                ids=[doc_id]
            )
            
            return doc_id
            
        except Exception as e:
            print(f"Error adding report to vector store: {e}")
            return ""
    
    def search_similar_incidents(self, query: str, n_results: int = 3) -> List[str]:
        """
        Search for similar past incidents based on the query.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of similar incident documents
        """
        try:
            # Query the collection
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            # Extract documents from results
            documents = results.get("documents", [])
            if documents and len(documents) > 0:
                return documents[0]
            
            return []
            
        except Exception as e:
            print(f"Error searching vector store: {e}")
            return []
    
    def get_all_reports(self) -> List[dict]:
        """
        Retrieve all stored reports from the vector store.
        
        Returns:
            List of all report metadata
        """
        try:
            # Get all documents from collection
            results = self.collection.get()
            
            reports = []
            if results.get("metadatas"):
                for i, metadata in enumerate(results["metadatas"]):
                    reports.append({
                        "id": results["ids"][i] if results.get("ids") else "",
                        **metadata
                    })
            
            return reports
            
        except Exception as e:
            print(f"Error retrieving all reports: {e}")
            return []
    
    def delete_report(self, doc_id: str) -> bool:
        """
        Delete a report from the vector store.
        
        Args:
            doc_id: Document ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.collection.delete(ids=[doc_id])
            return True
        except Exception as e:
            print(f"Error deleting report: {e}")
            return False
    
    def clear_collection(self) -> bool:
        """
        Clear all documents from the collection.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete and recreate collection
            self.client.delete_collection(name=self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_function
            )
            return True
        except Exception as e:
            print(f"Error clearing collection: {e}")
            return False
    
    def _create_searchable_text(self, report: dict, query: str) -> str:
        """
        Create a searchable text representation of the report.
        
        Args:
            report: Incident report dictionary
            query: Original query
            
        Returns:
            Searchable text string
        """
        text_parts = [
            f"Query: {query}",
            f"Threat Type: {report.get('threat_type', '')}",
            f"Severity: {report.get('severity', '')}",
            f"Summary: {report.get('summary', '')}",
        ]
        
        # Add affected systems
        if report.get('affected_systems'):
            text_parts.append(f"Affected Systems: {', '.join(report['affected_systems'])}")
        
        # Add CVE references
        if report.get('cve_references'):
            text_parts.append(f"CVE References: {', '.join(report['cve_references'])}")
        
        # Add indicators
        if report.get('indicators'):
            text_parts.append(f"Indicators: {', '.join(report['indicators'])}")
        
        # Add mitigation steps
        if report.get('mitigation_steps'):
            text_parts.append(f"Mitigation Steps: {'; '.join(report['mitigation_steps'])}")
        
        return " | ".join(text_parts)
    
    def get_stats(self) -> dict:
        """
        Get statistics about the vector store.
        
        Returns:
            Dictionary with stats
        """
        try:
            count = self.collection.count()
            reports = self.get_all_reports()
            
            high_severity = sum(1 for r in reports if r.get("severity") in ["high", "critical"])
            
            return {
                "total_reports": count,
                "high_severity_count": high_severity
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {
                "total_reports": 0,
                "high_severity_count": 0
            }


# Singleton instance for easy access
_vector_store_instance: Optional[VectorStore] = None


def get_vector_store() -> VectorStore:
    """
    Get the singleton instance of the vector store.
    
    Returns:
        VectorStore instance
    """
    global _vector_store_instance
    if _vector_store_instance is None:
        _vector_store_instance = VectorStore()
    return _vector_store_instance
