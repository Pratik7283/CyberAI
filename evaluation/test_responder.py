"""
Responder Evaluation Script for CyberSentinel Lite.

Tests the Responder Agent's ability to:
1. Correctly classify severity based on CVSS scores
2. Generate accurate summaries
3. Provide actionable mitigation steps

This is a rule-based evaluation - we compare actual outputs against expected values based on known CVSS scores.
"""

import os
import sys
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.responder import ResponderAgent


class ResponderEvaluator:
    """
    Evaluator for the Responder Agent component.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self.responder = ResponderAgent()
        self.test_results = []
    
    def create_test_cases(self) -> List[Dict[str, Any]]:
        """
        Create test cases with expected severity based on known CVSS scores.
        
        CVSS Score Ranges:
        - 0.0-3.9: Low
        - 4.0-6.9: Medium
        - 7.0-8.9: High
        - 9.0-10.0: Critical
        
        Returns:
            List of test cases with CVE data and expected severity
        """
        return [
            {
                "cve_id": "CVE-2024-3094",
                "cvss_score": 10.0,
                "expected_severity": "critical",
                "description": "XZ Utils backdoor (CVSS 10.0)"
            },
            {
                "cve_id": "CVE-2023-23397",
                "cvss_score": 9.8,
                "expected_severity": "critical",
                "description": "Microsoft Outlook NTLM theft (CVSS 9.8)"
            },
            {
                "cve_id": "CVE-2024-20767",
                "cvss_score": 7.8,
                "expected_severity": "high",
                "description": "Adobe ColdFusion RCE (CVSS 7.8)"
            },
            {
                "cve_id": "CVE-2023-38408",
                "cvss_score": 5.3,
                "expected_severity": "medium",
                "description": "OpenSSH regreSSHion (CVSS 5.3)"
            },
            {
                "cve_id": "CVE-2023-38545",
                "cvss_score": 3.9,
                "expected_severity": "low",
                "description": "OpenSSL buffer overflow (CVSS 3.9)"
            }
        ]
    
    def create_mock_investigation_result(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a mock investigation result with CVE data.
        
        Args:
            test_case: Test case with CVE information
            
        Returns:
            Mock investigation result
        """
        return {
            "query": test_case["cve_id"],
            "query_type": "cve",
            "past_incidents": [],
            "tool_calls": [
                {
                    "tool": "nvd_lookup",
                    "args": {"cve_id": test_case["cve_id"]},
                    "result": {
                        "cve_id": test_case["cve_id"],
                        "cvss_score": test_case["cvss_score"],
                        "description": f"Test vulnerability for {test_case['description']}",
                        "severity": "unknown"  # Let responder determine this
                    }
                }
            ],
            "raw_data": [
                f"CVE ID: {test_case['cve_id']}",
                f"CVSS Score: {test_case['cvss_score']}",
                f"Description: {test_case['description']}"
            ],
            "source_from_cache": False
        }
    
    def evaluate_single(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single test case.
        
        Args:
            test_case: Test case with CVE and expected severity
            
        Returns:
            Evaluation result with actual severity and pass/fail status
        """
        cve_id = test_case["cve_id"]
        expected_severity = test_case["expected_severity"]
        cvss_score = test_case["cvss_score"]
        
        # Create mock investigation result
        investigation = self.create_mock_investigation_result(test_case)
        
        # Run responder with correct parameters
        report = self.responder.generate_report(
            query=test_case["cve_id"],
            query_type="cve",
            investigation_data=investigation,
            past_incidents=[]
        )
        
        # Get actual severity
        actual_severity = report.get("severity", "unknown").lower()
        
        # Normalize severity values
        severity_map = {
            "critical": ["critical", "crit"],
            "high": ["high"],
            "medium": ["medium", "moderate"],
            "low": ["low"]
        }
        
        # Check if actual severity matches expected
        severity_match = False
        for key, variants in severity_map.items():
            if key == expected_severity and actual_severity in variants:
                severity_match = True
                break
        
        # Check if CVSS score is in report
        cvss_in_report = str(cvss_score) in str(report)
        
        # Check if summary is not empty
        has_summary = bool(report.get("summary"))
        
        # Check if mitigation steps are provided
        has_mitigation = bool(report.get("mitigation_steps"))
        
        # Overall pass
        passed = severity_match and cvss_in_report and has_summary and has_mitigation
        
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "expected_severity": expected_severity,
            "actual_severity": actual_severity,
            "severity_match": severity_match,
            "cvss_in_report": cvss_in_report,
            "has_summary": has_summary,
            "has_mitigation": has_mitigation,
            "passed": passed,
            "description": test_case["description"]
        }
    
    def evaluate(self):
        """
        Run evaluation on all test cases.
        """
        test_cases = self.create_test_cases()
        
        print("="*60)
        print("Responder Evaluation for CyberSentinel Lite")
        print("="*60)
        print(f"\nRunning {len(test_cases)} test cases...\n")
        
        for test_case in test_cases:
            result = self.evaluate_single(test_case)
            self.test_results.append(result)
            
            # Print result
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"{status}: {test_case['cve_id']} (CVSS {result['cvss_score']})")
            print(f"  Severity: {result['actual_severity']} (expected: {result['expected_severity']})")
            print(f"  CVSS in report: {result['cvss_in_report']}")
            print(f"  Has summary: {result['has_summary']}")
            print(f"  Has mitigation: {result['has_mitigation']}")
            print(f"  Description: {result['description']}")
            print()
        
        # Calculate metrics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["passed"])
        severity_accuracy = sum(1 for r in self.test_results if r["severity_match"]) / total
        cvss_accuracy = sum(1 for r in self.test_results if r["cvss_in_report"]) / total
        summary_rate = sum(1 for r in self.test_results if r["has_summary"]) / total
        mitigation_rate = sum(1 for r in self.test_results if r["has_mitigation"]) / total
        overall_accuracy = passed / total
        
        print("="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Overall Accuracy: {overall_accuracy:.2%}")
        print(f"Severity Classification Accuracy: {severity_accuracy:.2%}")
        print(f"CVSS Score Inclusion Rate: {cvss_accuracy:.2%}")
        print(f"Summary Generation Rate: {summary_rate:.2%}")
        print(f"Mitigation Steps Rate: {mitigation_rate:.2%}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "overall_accuracy": overall_accuracy,
            "severity_accuracy": severity_accuracy,
            "cvss_accuracy": cvss_accuracy,
            "summary_rate": summary_rate,
            "mitigation_rate": mitigation_rate
        }


if __name__ == "__main__":
    evaluator = ResponderEvaluator()
    evaluator.evaluate()
