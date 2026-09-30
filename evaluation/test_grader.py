"""
Grader Evaluation Script for CyberSentinel Lite.

Tests the Corrective RAG Grader's ability to:
1. Correctly identify relevant documents
2. Correctly identify irrelevant documents
3. Provide accurate overall grades

This is a rule-based evaluation - we compare actual grades against expected relevance.
"""

import os
import sys
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.corrective_rag import CorrectiveRAG


class GraderEvaluator:
    """
    Evaluator for the Corrective RAG Grader component.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self.grader = CorrectiveRAG()
        self.test_results = []
    
    def create_test_cases(self) -> List[Dict[str, Any]]:
        """
        Create test cases with documents and expected relevance.
        
        Returns:
            List of test cases with queries, documents, and expected grades
        """
        return [
            {
                "query": "CVE-2024-3094",
                "documents": [
                    "CVE-2024-3094 is a critical vulnerability in XZ Utils with a backdoor that allows remote code execution. CVSS score: 10.0.",
                    "XZ Utils versions 5.6.0 and 5.6.1 are affected by this vulnerability."
                ],
                "expected_grade": "relevant",
                "description": "Relevant document about the CVE"
            },
            {
                "query": "CVE-2024-3094",
                "documents": [
                    "Phishing is a social engineering attack where attackers impersonate legitimate entities to steal sensitive information."
                ],
                "expected_grade": "irrelevant",
                "description": "Irrelevant document about phishing"
            },
            {
                "query": "phishing",
                "documents": [
                    "Phishing is a social engineering attack where attackers impersonate legitimate entities to steal sensitive information.",
                    "Recent phishing trends include business email compromise (BEC) and SMS phishing (smishing)."
                ],
                "expected_grade": "relevant",
                "description": "Relevant document about phishing"
            },
            {
                "query": "phishing",
                "documents": [
                    "CVE-2024-3094 is a critical vulnerability in XZ Utils with a backdoor that allows remote code execution."
                ],
                "expected_grade": "irrelevant",
                "description": "Irrelevant document about CVE"
            },
            {
                "query": "192.168.1.1",
                "documents": [
                    "IP 192.168.1.1 has been reported for malicious activity including port scanning and brute force attacks.",
                    "This IP address has a high abuse confidence score of 85%."
                ],
                "expected_grade": "relevant",
                "description": "Relevant document about the IP"
            },
            {
                "query": "192.168.1.1",
                "documents": [
                    "Ransomware is malicious software that encrypts files and demands payment for decryption."
                ],
                "expected_grade": "irrelevant",
                "description": "Irrelevant document about ransomware"
            }
        ]
    
    def evaluate_single(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single test case.
        
        Args:
            test_case: Test case with query, documents, and expected grade
            
        Returns:
            Evaluation result with actual grade and pass/fail status
        """
        query = test_case["query"]
        documents = test_case["documents"]
        expected_grade = test_case["expected_grade"]
        
        # Run grader
        grade_result = self.grader.grade_documents(query, documents)
        
        # Get actual overall grade
        actual_grade = grade_result.get("overall_grade", "unknown")
        
        # Check if grade matches
        grade_match = actual_grade == expected_grade
        
        # Check individual document counts
        relevant_count = len(grade_result.get("relevant_docs", []))
        irrelevant_count = len(grade_result.get("irrelevant_docs", []))
        total_docs = len(documents)
        
        # For relevant expected, at least one document should be relevant
        # For irrelevant expected, all documents should be irrelevant
        if expected_grade == "relevant":
            individual_match = relevant_count > 0
        else:
            individual_match = irrelevant_count == total_docs
        
        passed = grade_match and individual_match
        
        return {
            "query": query,
            "documents_count": len(documents),
            "expected_grade": expected_grade,
            "actual_grade": actual_grade,
            "grade_match": grade_match,
            "relevant_count": relevant_count,
            "total_docs": total_docs,
            "individual_match": individual_match,
            "passed": passed,
            "description": test_case["description"]
        }
    
    def evaluate(self):
        """
        Run evaluation on all test cases.
        """
        test_cases = self.create_test_cases()
        
        print("="*60)
        print("Grader Evaluation for CyberSentinel Lite")
        print("="*60)
        print(f"\nRunning {len(test_cases)} test cases...\n")
        
        for test_case in test_cases:
            result = self.evaluate_single(test_case)
            self.test_results.append(result)
            
            # Print result
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"{status}: {test_case['query']}")
            print(f"  Expected: {result['expected_grade']}, Actual: {result['actual_grade']}")
            print(f"  Relevant docs: {result['relevant_count']}/{result['total_docs']}")
            print(f"  Description: {result['description']}")
            print()
        
        # Calculate metrics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["passed"])
        grade_accuracy = sum(1 for r in self.test_results if r["grade_match"]) / total
        individual_accuracy = sum(1 for r in self.test_results if r["individual_match"]) / total
        overall_accuracy = passed / total
        
        print("="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Overall Accuracy: {overall_accuracy:.2%}")
        print(f"Overall Grade Accuracy: {grade_accuracy:.2%}")
        print(f"Individual Document Accuracy: {individual_accuracy:.2%}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "overall_accuracy": overall_accuracy,
            "grade_accuracy": grade_accuracy,
            "individual_accuracy": individual_accuracy
        }


if __name__ == "__main__":
    evaluator = GraderEvaluator()
    evaluator.evaluate()
