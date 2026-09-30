"""
NewsAPI Tool for CyberSentinel Lite.

This module provides functions to search for cybersecurity news using the NewsAPI.
Requires an API key from https://newsapi.org/
"""

import os
import httpx
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class NewsTool:
    """
    Tool for interacting with the NewsAPI.
    """
    
    BASE_URL = "https://newsapi.org/v2"
    
    def __init__(self):
        """
        Initialize the NewsAPI tool.
        """
        self.api_key = os.getenv("NEWS_API_KEY")
        if not self.api_key:
            print("Warning: NEWS_API_KEY not found in environment variables")
        
        self.client = httpx.Client(
            timeout=30.0,
            headers={"X-API-Key": self.api_key} if self.api_key else {}
        )
    
    def search_cybersecurity_news(self, query: str, page_size: int = 10) -> List[Dict[str, Any]]:
        """
        Search for cybersecurity-related news articles.
        
        Args:
            query: Search query/keyword
            page_size: Number of results to return (default: 10)
            
        Returns:
            List of news article dictionaries
        """
        try:
            if not self.api_key:
                return [{"error": "NEWS_API_KEY not configured"}]
            
            # Enhance query with cybersecurity terms
            enhanced_query = f"{query} cybersecurity OR security OR threat OR hack OR breach"
            
            # Make API request
            params = {
                "q": enhanced_query,
                "language": "en",
                "sortBy": "publishedAt",
                "pageSize": page_size
            }
            response = self.client.get(f"{self.BASE_URL}/everything", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse and return results
            articles = []
            if data.get("status") == "ok" and data.get("articles"):
                for article in data["articles"]:
                    articles.append(self._parse_article(article))
            
            return articles
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return [{"error": "Invalid API key"}]
            elif e.response.status_code == 426:
                return [{"error": "API key requires upgrade"}]
            return [{"error": f"HTTP error: {e.response.status_code}"}]
        except Exception as e:
            return [{"error": f"Error searching news: {str(e)}"}]
    
    def search_tech_news(self, query: str, page_size: int = 10) -> List[Dict[str, Any]]:
        """
        Search for technology news (broader category).
        
        Args:
            query: Search query/keyword
            page_size: Number of results to return (default: 10)
            
        Returns:
            List of news article dictionaries
        """
        try:
            if not self.api_key:
                return [{"error": "NEWS_API_KEY not configured"}]
            
            # Make API request with technology category
            params = {
                "q": query,
                "category": "technology",
                "language": "en",
                "sortBy": "publishedAt",
                "pageSize": page_size
            }
            response = self.client.get(f"{self.BASE_URL}/everything", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse and return results
            articles = []
            if data.get("status") == "ok" and data.get("articles"):
                for article in data["articles"]:
                    articles.append(self._parse_article(article))
            
            return articles
            
        except httpx.HTTPStatusError as e:
            return [{"error": f"HTTP error: {e.response.status_code}"}]
        except Exception as e:
            return [{"error": f"Error searching tech news: {str(e)}"}]
    
    def _parse_article(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw article data from NewsAPI into a structured format.
        
        Args:
            article: Raw article data from NewsAPI
            
        Returns:
            Parsed article dictionary
        """
        try:
            return {
                "title": article.get("title", ""),
                "description": article.get("description", ""),
                "content": article.get("content", ""),
                "url": article.get("url", ""),
                "url_to_image": article.get("urlToImage", ""),
                "published_at": article.get("publishedAt", ""),
                "source": article.get("source", {}).get("name", ""),
                "author": article.get("author", "")
            }
        except Exception as e:
            return {
                "error": f"Error parsing article: {str(e)}",
                "title": article.get("title", "Unknown")
            }
    
    def extract_keywords(self, text: str) -> List[str]:
        """
        Extract potential threat keywords from text.
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of extracted keywords
        """
        # Common cybersecurity threat keywords
        threat_keywords = [
            "ransomware", "malware", "phishing", "ddos", "zero-day",
            "vulnerability", "exploit", "breach", "hack", "attack",
            "cve", "botnet", "spyware", "trojan", "backdoor"
        ]
        
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in threat_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def close(self):
        """
        Close the HTTP client.
        """
        self.client.close()


# Singleton instance
_news_tool_instance: Optional[NewsTool] = None


def get_news_tool() -> NewsTool:
    """
    Get the singleton instance of the NewsAPI tool.
    
    Returns:
        NewsTool instance
    """
    global _news_tool_instance
    if _news_tool_instance is None:
        _news_tool_instance = NewsTool()
    return _news_tool_instance
