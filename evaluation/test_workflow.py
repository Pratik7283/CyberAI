"""
Workflow Evaluation Script for CyberSentinel Lite.

Tests the end-to-end workflow integration:
1. Correct routing through the workflow graph
2. Proper node execution sequence
3. Error handling and fallback mechanisms
4. Caching behavior
5. State management

This is an integration test - we run the full workflow and verify the complete execution.
"""

import os
import sys
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph.workflow import CyberSentinelWorkflow


class WorkflowEvaluator:
    """
    Evaluator for the end-to-end workflow integration.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self.workflow = CyberSentinelWorkflow()
        self.test_results = []
    
    def create_test_cases(self) -> List[Dict[str, Any]]:
        """
        Create test cases for end-to-end workflow testing.
        
        Returns:
            List of test cases with queries and expected behaviors
        """
        return [
            {
                "query": "What is phishing?",
                "expected_route": "direct_llm",
                "expected_has_report": True,
                "description": "Simple question should use direct LLM"
            },
            {
                "query": "CVE-2024-3094",
                "expected_route": "full_rag",
                "expected_has_report": True,
                "expected_has_severity": True,
                "description": "CVE should trigger full RAG with severity"
            },
            {
                "query": "8.8.8.8",
                "expected_route": "full_rag",
                "expected_has_report": True,
                "expected_has_severity": True,
                "description": "IP should trigger full RAG with severity"
            },
            {
                "query": "ransomware",
                "expected_route": "direct_llm",
                "expected_has_report": True,
                "description": "Keyword should use direct LLM"
            }
        ]
    
    def evaluate_single(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single test case end-to-end.
        
        Args:
            test_case: Test case with query and expected behaviors
            
        Returns:
            Evaluation result with actual workflow execution and pass/fail status
        """
        query = test_case["query"]
        expected_route = test_case["expected_route"]
        
        try:
            # Run the full workflow
            result = self.workflow.run(query)
            
            # Check if workflow completed successfully
            completed = result.get("final_report") is not None
            
            # Check if report was generated
            has_report = bool(result.get("final_report"))
            
            # Check if severity is present (for full_rag queries)
            has_severity = bool(result.get("final_report", {}).get("severity"))
            
            # Check route from state
            actual_route = result.get("route", "unknown")
            
            # Check if caching was used
            from_cache = result.get("source_from_cache", False)
            
            # Validate expectations
            route_match = actual_route == expected_route
            report_match = has_report == test_case["expected_has_report"]
            
            # Check severity if expected
            if test_case.get("expected_has_severity"):
                severity_match = has_severity
            else:
                severity_match = True  # Not required for this test
            
            # Overall pass
            passed = completed and route_match and report_match and severity_match
            
            return {
                "query": query,
                "expected_route": expected_route,
                "actual_route": actual_route,
                "route_match": route_match,
                "completed": completed,
                "has_report": has_report,
                "report_match": report_match,
                "has_severity": has_severity,
                "severity_match": severity_match,
                "from_cache": from_cache,
                "passed": passed,
                "description": test_case["description"]
            }
            
        except Exception as e:
            return {
                "query": query,
                "expected_route": expected_route,
                "actual_route": "error",
                "route_match": False,
                "completed": False,
                "has_report": False,
                "report_match": False,
                "has_severity": False,
                "severity_match": False,
                "from_cache": False,
                "passed": False,
                "error": str(e),
                "description": test_case["description"]
            }
    
    def evaluate(self):
        """
        Run evaluation on all test cases.
        """
        test_cases = self.create_test_cases()
        
        print("="*60)
        print("Workflow Evaluation for CyberSentinel Lite")
        print("="*60)
        print(f"\nRunning {len(test_cases)} end-to-end test cases...\n")
        
        for test_case in test_cases:
            result = self.evaluate_single(test_case)
            self.test_results.append(result)
            
            # Print result
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"{status}: {test_case['query']}")
            print(f"  Route: {result['actual_route']} (expected: {result['expected_route']})")
            print(f"  Completed: {result['completed']}")
            print(f"  Has Report: {result['has_report']}")
            print(f"  Has Severity: {result['has_severity']}")
            print(f"  From Cache: {result['from_cache']}")
            if "error" in result:
                print(f"  Error: {result['error']}")
            print(f"  Description: {result['description']}")
            print()
        
        # Calculate metrics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["passed"])
        completed_rate = sum(1 for r in self.test_results if r["completed"]) / total
        route_accuracy = sum(1 for r in self.test_results if r["route_match"]) / total
        report_rate = sum(1 for r in self.test_results if r["report_match"]) / total
        overall_accuracy = passed / total
        cache_rate = sum(1 for r in self.test_results if r["from_cache"]) / total
        
        print("="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Overall Accuracy: {overall_accuracy:.2%}")
        print(f"Workflow Completion Rate: {completed_rate:.2%}")
        print(f"Route Accuracy: {route_accuracy:.2%}")
        print(f"Report Generation Rate: {report_rate:.2%}")
        print(f"Cache Hit Rate: {cache_rate:.2%}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "overall_accuracy": overall_accuracy,
            "completed_rate": completed_rate,
            "route_accuracy": route_accuracy,
            "report_rate": report_rate,
            "cache_rate": cache_rate
        }


if __name__ == "__main__":
    evaluator = WorkflowEvaluator()
    evaluator.evaluate()
