"""
Investigator Evaluation Script for CyberSentinel Lite.

Tests the Investigator Agent's ability to:
1. Correctly extract CVE IDs from natural language queries
2. Correctly extract IP addresses from natural language queries
3. Select the appropriate tool (NVD, AbuseIPDB, NewsAPI) based on query type

This is a rule-based evaluation - we compare actual outputs against expected values.
"""

import os
import sys
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.investigator import InvestigatorAgent
from memory.vector_store import VectorStore


class InvestigatorEvaluator:
    """
    Evaluator for the Investigator Agent component.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self.investigator = InvestigatorAgent()
        self.test_results = []
    
    def create_test_cases(self) -> List[Dict[str, Any]]:
        """
        Create test cases with expected outputs.
        
        Returns:
            List of test cases with queries and expected extractions
        """
        return [
            {
                "query": "CVE-2024-3094",
                "query_type": "cve",
                "expected_cve": "CVE-2024-3094",
                "expected_tool": "nvd_lookup",
                "description": "Direct CVE ID extraction"
            },
            {
                "query": "Check CVE-2023-23397",
                "query_type": "cve",
                "expected_cve": "CVE-2023-23397",
                "expected_tool": "nvd_lookup",
                "description": "CVE ID in natural language"
            },
            {
                "query": "Tell me about CVE-2024-20767",
                "query_type": "cve",
                "expected_cve": "CVE-2024-20767",
                "expected_tool": "nvd_lookup",
                "description": "CVE ID in sentence"
            },
            {
                "query": "192.168.1.1",
                "query_type": "ip",
                "expected_ip": "192.168.1.1",
                "expected_tool": "abuseipdb_check",
                "description": "Direct IP address"
            },
            {
                "query": "Is 8.8.8.8 safe?",
                "query_type": "ip",
                "expected_ip": "8.8.8.8",
                "expected_tool": "abuseipdb_check",
                "description": "IP address in question"
            },
            {
                "query": "Check reputation of 1.1.1.1",
                "query_type": "ip",
                "expected_ip": "1.1.1.1",
                "expected_tool": "abuseipdb_check",
                "description": "IP address in command"
            },
            {
                "query": "ransomware",
                "query_type": "keyword",
                "expected_tool": "news_search",
                "description": "Keyword should trigger news search"
            },
            {
                "query": "phishing attacks",
                "query_type": "keyword",
                "expected_tool": "news_search",
                "description": "Multi-word keyword"
            }
        ]
    
    def evaluate_single(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single test case.
        
        Args:
            test_case: Test case with query and expected outputs
            
        Returns:
            Evaluation result with actual outputs and pass/fail status
        """
        query = test_case["query"]
        query_type = test_case["query_type"]
        
        # Run investigator
        result = self.investigator.investigate_direct(query, query_type)
        
        # Extract actual values
        tool_calls = result.get("tool_calls", [])
        actual_tool = tool_calls[0]["tool"] if tool_calls else "none"
        
        # Check tool match
        tool_match = actual_tool == test_case["expected_tool"]
        
        # Check extraction based on query type
        extraction_match = True
        extracted_value = None
        
        if query_type == "cve":
            # Check if expected CVE is in the raw data or tool args
            expected_cve = test_case["expected_cve"]
            raw_data = " ".join(result.get("raw_data", []))
            tool_args = str(tool_calls[0].get("args", {})) if tool_calls else ""
            extraction_match = expected_cve in raw_data or expected_cve in tool_args
            extracted_value = expected_cve if extraction_match else "not found"
            
        elif query_type == "ip":
            # Check if expected IP is in the raw data or tool args
            expected_ip = test_case["expected_ip"]
            raw_data = " ".join(result.get("raw_data", []))
            tool_args = str(tool_calls[0].get("args", {})) if tool_calls else ""
            extraction_match = expected_ip in raw_data or expected_ip in tool_args
            extracted_value = expected_ip if extraction_match else "not found"
        
        else:  # keyword
            extraction_match = True  # No extraction needed for keywords
            extracted_value = "N/A"
        
        passed = tool_match and extraction_match
        
        return {
            "query": query,
            "query_type": query_type,
            "expected_tool": test_case["expected_tool"],
            "actual_tool": actual_tool,
            "tool_match": tool_match,
            "expected_extraction": test_case.get("expected_cve") or test_case.get("expected_ip") or "N/A",
            "actual_extraction": extracted_value,
            "extraction_match": extraction_match,
            "passed": passed,
            "description": test_case["description"]
        }
    
    def evaluate(self):
        """
        Run evaluation on all test cases.
        """
        test_cases = self.create_test_cases()
        
        print("="*60)
        print("Investigator Evaluation for CyberSentinel Lite")
        print("="*60)
        print(f"\nRunning {len(test_cases)} test cases...\n")
        
        for test_case in test_cases:
            result = self.evaluate_single(test_case)
            self.test_results.append(result)
            
            # Print result
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"{status}: {test_case['query']}")
            print(f"  Tool: {result['actual_tool']} (expected: {result['expected_tool']})")
            print(f"  Extraction: {result['actual_extraction']} (expected: {result['expected_extraction']})")
            print(f"  Description: {result['description']}")
            print()
        
        # Calculate metrics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["passed"])
        tool_accuracy = sum(1 for r in self.test_results if r["tool_match"]) / total
        extraction_accuracy = sum(1 for r in self.test_results if r["extraction_match"]) / total
        overall_accuracy = passed / total
        
        print("="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Overall Accuracy: {overall_accuracy:.2%}")
        print(f"Tool Selection Accuracy: {tool_accuracy:.2%}")
        print(f"Extraction Accuracy: {extraction_accuracy:.2%}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "overall_accuracy": overall_accuracy,
            "tool_accuracy": tool_accuracy,
            "extraction_accuracy": extraction_accuracy
        }


if __name__ == "__main__":
    evaluator = InvestigatorEvaluator()
    evaluator.evaluate()
