"""
NVD (National Vulnerability Database) API Tool for CyberSentinel Lite.

This module provides functions to query the NVD CVE API for vulnerability information.
No API key is required for the NVD API.
"""

import httpx
from typing import Optional, Dict, Any
import re


class NVDTool:
    """
    Tool for interacting with the NVD CVE API.
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        """
        Initialize the NVD tool.
        """
        self.client = httpx.Client(timeout=30.0)
    
    def extract_cve_id(self, query: str) -> Optional[str]:
        """
        Extract CVE ID from a query string.
        
        Args:
            query: Input string that may contain a CVE ID
            
        Returns:
            CVE ID if found, None otherwise
        """
        # Pattern to match CVE IDs (e.g., CVE-2024-1234, CVE-2023-99999)
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        match = re.search(cve_pattern, query, re.IGNORECASE)
        
        if match:
            return match.group(0).upper()
        return None
    
    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Look up a specific CVE by ID.
        
        Args:
            cve_id: The CVE ID to look up (e.g., CVE-2024-1234)
            
        Returns:
            Dictionary containing CVE information
        """
        try:
            # Normalize CVE ID format
            cve_id = cve_id.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            
            # Make API request
            params = {"cveId": cve_id}
            response = self.client.get(self.BASE_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract relevant information
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                cve_item = data["vulnerabilities"][0]["cve"]
                return self._parse_cve_data(cve_item)
            
            return {"error": "CVE not found"}
            
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"Error fetching CVE data: {str(e)}"}
    
    def search_cves(self, keyword: str, limit: int = 5) -> list:
        """
        Search for CVEs by keyword.
        
        Args:
            keyword: Search keyword
            limit: Maximum number of results to return
            
        Returns:
            List of CVE dictionaries
        """
        try:
            # Make API request with keyword search
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": limit
            }
            response = self.client.get(self.BASE_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse and return results
            results = []
            if data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"]:
                    cve_data = self._parse_cve_data(vuln["cve"])
                    results.append(cve_data)
            
            return results
            
        except httpx.HTTPStatusError as e:
            return [{"error": f"HTTP error: {e.response.status_code}"}]
        except Exception as e:
            return [{"error": f"Error searching CVEs: {str(e)}"}]
    
    def _parse_cve_data(self, cve_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw CVE data from NVD API into a structured format.
        
        Args:
            cve_item: Raw CVE data from NVD API
            
        Returns:
            Parsed CVE dictionary
        """
        try:
            cve_id = cve_item.get("id", "Unknown")
            
            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS score and severity
            metrics = cve_item.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            
            # Try to get CVSS v3.1 score first, then v3.0, then v2
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = "MEDIUM"  # V2 doesn't have severity, default to MEDIUM
            
            # Extract affected products
            affected_systems = []
            configurations = cve_item.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_str = cpe_match.get("criteria", "")
                            # Simplify CPE string
                            if cpe_str:
                                parts = cpe_str.split(":")
                                if len(parts) >= 5:
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 else ""
                                    affected_systems.append(f"{product} {version}".strip())
            
            # Remove duplicates
            affected_systems = list(set(affected_systems))
            
            # Extract references
            references = cve_item.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references if ref.get("url")]
            
            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "affected_systems": affected_systems[:10],  # Limit to 10
                "references": ref_urls[:5],  # Limit to 5
                "published_date": cve_item.get("published", ""),
                "modified_date": cve_item.get("lastModified", "")
            }
            
        except Exception as e:
            return {
                "error": f"Error parsing CVE data: {str(e)}",
                "cve_id": cve_item.get("id", "Unknown")
            }
    
    def close(self):
        """
        Close the HTTP client.
        """
        self.client.close()


# Singleton instance
_nvd_tool_instance: Optional[NVDTool] = None


def get_nvd_tool() -> NVDTool:
    """
    Get the singleton instance of the NVD tool.
    
    Returns:
        NVDTool instance
    """
    global _nvd_tool_instance
    if _nvd_tool_instance is None:
        _nvd_tool_instance = NVDTool()
    return _nvd_tool_instance
