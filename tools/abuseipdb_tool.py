"""
AbuseIPDB API Tool for CyberSentinel Lite.

This module provides functions to check IP address reputation using the AbuseIPDB API.
Requires an API key from https://www.abuseipdb.com/
"""

import os
import httpx
from typing import Optional, Dict, Any
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class AbuseIPDBTool:
    """
    Tool for interacting with the AbuseIPDB API.
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self):
        """
        Initialize the AbuseIPDB tool.
        """
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            print("Warning: ABUSEIPDB_API_KEY not found in environment variables")
        
        self.client = httpx.Client(
            timeout=30.0,
            headers={"Key": self.api_key} if self.api_key else {}
        )
    
    def extract_ip_address(self, query: str) -> Optional[str]:
        """
        Extract IP address from a query string.
        
        Args:
            query: Input string that may contain an IP address
            
        Returns:
            IP address if found, None otherwise
        """
        # Pattern to match IPv4 addresses
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ipv4_pattern, query)
        
        if match:
            ip = match.group(0)
            # Validate IP address format
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return ip
        return None
    
    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """
        Check the reputation of an IP address.
        
        Args:
            ip_address: The IP address to check
            max_age_in_days: Maximum age of reports to consider (default: 90)
            
        Returns:
            Dictionary containing IP reputation information
        """
        try:
            if not self.api_key:
                return {"error": "ABUSEIPDB_API_KEY not configured"}
            
            # Make API request
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_in_days,
                "verbose": ""
            }
            response = self.client.get(f"{self.BASE_URL}/check", params=params)
            response.raise_for_status()
            
            data = response.json()
            return self._parse_ip_data(data)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"error": "Invalid API key"}
            elif e.response.status_code == 422:
                return {"error": "Invalid IP address format"}
            return {"error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"Error checking IP: {str(e)}"}
    
    def report_ip(self, ip_address: str, categories: list, comment: str) -> Dict[str, Any]:
        """
        Report an IP address for abusive activity.
        
        Args:
            ip_address: The IP address to report
            categories: List of category IDs (see AbuseIPDB documentation)
            comment: Comment describing the abuse
            
        Returns:
            Dictionary containing report response
        """
        try:
            if not self.api_key:
                return {"error": "ABUSEIPDB_API_KEY not configured"}
            
            # Make API request
            data = {
                "ip": ip_address,
                "categories": categories,
                "comment": comment
            }
            response = self.client.post(f"{self.BASE_URL}/report", json=data)
            response.raise_for_status()
            
            return response.json()
            
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"Error reporting IP: {str(e)}"}
    
    def _parse_ip_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw IP data from AbuseIPDB API into a structured format.
        
        Args:
            data: Raw data from AbuseIPDB API
            
        Returns:
            Parsed IP dictionary
        """
        try:
            ip_info = data.get("data", {})
            
            ip_address = ip_info.get("ipAddress", "Unknown")
            abuse_confidence_score = ip_info.get("abuseConfidenceScore", 0)
            is_public = ip_info.get("isPublic", False)
            ip_version = ip_info.get("ipVersion", 0)
            country_code = ip_info.get("countryCode", "")
            country_name = ip_info.get("countryName", "")
            usage_type = ip_info.get("usageType", "")
            isp = ip_info.get("isp", "")
            domain = ip_info.get("domain", "")
            hostnames = ip_info.get("hostnames", [])
            total_reports = ip_info.get("totalReports", 0)
            last_reported_at = ip_info.get("lastReportedAt", "")
            
            # Determine severity based on abuse confidence score
            if abuse_confidence_score >= 75:
                severity = "critical"
            elif abuse_confidence_score >= 50:
                severity = "high"
            elif abuse_confidence_score >= 25:
                severity = "medium"
            else:
                severity = "low"
            
            # Extract report details if available
            reports = ip_info.get("reports", [])
            recent_reports = []
            for report in reports[:5]:  # Limit to 5 recent reports
                recent_reports.append({
                    "reported_at": report.get("reportedAt", ""),
                    "comment": report.get("comment", ""),
                    "categories": report.get("categories", [])
                })
            
            return {
                "ip_address": ip_address,
                "abuse_confidence_score": abuse_confidence_score,
                "severity": severity,
                "is_public": is_public,
                "ip_version": ip_version,
                "country_code": country_code,
                "country_name": country_name,
                "usage_type": usage_type,
                "isp": isp,
                "domain": domain,
                "hostnames": hostnames,
                "total_reports": total_reports,
                "last_reported_at": last_reported_at,
                "recent_reports": recent_reports
            }
            
        except Exception as e:
            return {
                "error": f"Error parsing IP data: {str(e)}",
                "ip_address": data.get("data", {}).get("ipAddress", "Unknown")
            }
    
    def close(self):
        """
        Close the HTTP client.
        """
        self.client.close()


# Singleton instance
_abuseipdb_tool_instance: Optional[AbuseIPDBTool] = None


def get_abuseipdb_tool() -> AbuseIPDBTool:
    """
    Get the singleton instance of the AbuseIPDB tool.
    
    Returns:
        AbuseIPDBTool instance
    """
    global _abuseipdb_tool_instance
    if _abuseipdb_tool_instance is None:
        _abuseipdb_tool_instance = AbuseIPDBTool()
    return _abuseipdb_tool_instance
