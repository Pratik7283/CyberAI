"""
Router Evaluation Script for CyberSentinel Lite.

Tests the Adaptive Router's ability to:
1. Correctly classify queries as direct_llm vs full_rag
2. Correctly identify query types (ip, cve, keyword)

This is a rule-based evaluation - we compare actual outputs against expected values.
"""

import os
import sys
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.adaptive_router import AdaptiveRouter


class RouterEvaluator:
    """
    Evaluator for the Adaptive Router component.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self.router = AdaptiveRouter()
        self.test_results = []
    
    def create_test_cases(self) -> List[Dict[str, Any]]:
        """
        Create test cases with expected outputs.
        
        Returns:
            List of test cases with queries and expected classifications
        """
        return [
            {
                "query": "What is phishing?",
                "expected_route": "direct_llm",
                "expected_type": "keyword",
                "description": "Simple conceptual question should use direct LLM"
            },
            {
                "query": "CVE-2024-3094",
                "expected_route": "full_rag",
                "expected_type": "cve",
                "description": "Specific CVE ID should trigger full RAG pipeline"
            },
            {
                "query": "Check 192.168.1.1",
                "expected_route": "full_rag",
                "expected_type": "ip",
                "description": "IP address should trigger full RAG pipeline"
            },
            {
                "query": "ransomware",
                "expected_route": "direct_llm",
                "expected_type": "keyword",
                "description": "General keyword should use direct LLM"
            },
            {
                "query": "Tell me about CVE-2023-23397",
                "expected_route": "full_rag",
                "expected_type": "cve",
                "description": "Natural language CVE query should trigger full RAG"
            },
            {
                "query": "Is 8.8.8.8 safe?",
                "expected_route": "full_rag",
                "expected_type": "ip",
                "description": "Natural language IP query should trigger full RAG"
            },
            {
                "query": "What is a DDoS attack?",
                "expected_route": "direct_llm",
                "expected_type": "keyword",
                "description": "Conceptual question should use direct LLM"
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
        expected_route = test_case["expected_route"]
        expected_type = test_case["expected_type"]
        
        # Run router
        result = self.router.route_query(query)
        
        # Compare actual vs expected
        route_match = result["route"] == expected_route
        type_match = result["query_type"] == expected_type
        
        passed = route_match and type_match
        
        return {
            "query": query,
            "expected_route": expected_route,
            "actual_route": result["route"],
            "expected_type": expected_type,
            "actual_type": result["query_type"],
            "route_match": route_match,
            "type_match": type_match,
            "passed": passed,
            "reason": result.get("reason", "")
        }
    
    def evaluate(self):
        """
        Run evaluation on all test cases.
        """
        test_cases = self.create_test_cases()
        
        print("="*60)
        print("Router Evaluation for CyberSentinel Lite")
        print("="*60)
        print(f"\nRunning {len(test_cases)} test cases...\n")
        
        for test_case in test_cases:
            result = self.evaluate_single(test_case)
            self.test_results.append(result)
            
            # Print result
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"{status}: {test_case['query']}")
            print(f"  Route: {result['actual_route']} (expected: {result['expected_route']})")
            print(f"  Type: {result['actual_type']} (expected: {result['expected_type']})")
            if not result["passed"]:
                print(f"  Reason: {result['reason']}")
            print()
        
        # Calculate metrics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["passed"])
        route_accuracy = sum(1 for r in self.test_results if r["route_match"]) / total
        type_accuracy = sum(1 for r in self.test_results if r["type_match"]) / total
        overall_accuracy = passed / total
        
        print("="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Overall Accuracy: {overall_accuracy:.2%}")
        print(f"Route Classification Accuracy: {route_accuracy:.2%}")
        print(f"Type Detection Accuracy: {type_accuracy:.2%}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "overall_accuracy": overall_accuracy,
            "route_accuracy": route_accuracy,
            "type_accuracy": type_accuracy
        }


if __name__ == "__main__":
    evaluator = RouterEvaluator()
    evaluator.evaluate()
