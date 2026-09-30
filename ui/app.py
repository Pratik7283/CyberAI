"""
Streamlit UI for CyberSentinel Lite.

This module provides a modern, user-friendly interface for the threat analysis system.
"""

import os
import sys
from datetime import datetime
import streamlit as st
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph.workflow import get_workflow
from memory.vector_store import get_vector_store

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="CyberSentinel Lite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-critical {
        background-color: #ff4d4d;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .severity-high {
        background-color: #ff9f43;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .severity-medium {
        background-color: #feca57;
        color: black;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .severity-low {
        background-color: #1dd1a1;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        font-weight: bold;
    }
    .summary-card {
        background-color: #f8f9fa;
        color: #1a1a1a;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 1rem 0;
    }
    .mitigation-step {
        background-color: #e3f2fd;
        color: #1a1a1a;
        padding: 0.75rem;
        margin: 0.5rem 0;
        border-radius: 0.25rem;
        border-left: 3px solid #2196f3;
    }
    .source-tag {
        background-color: #6c757d;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.875rem;
    }
</style>
""", unsafe_allow_html=True)


def render_severity_badge(severity: str):
    """
    Render a severity badge with appropriate color.
    
    Args:
        severity: Severity level (critical, high, medium, low)
    """
    severity = severity.lower() if severity else "unknown"
    
    if severity == "critical":
        st.markdown('<span class="severity-critical">🔴 CRITICAL</span>', unsafe_allow_html=True)
    elif severity == "high":
        st.markdown('<span class="severity-high">🟠 HIGH</span>', unsafe_allow_html=True)
    elif severity == "medium":
        st.markdown('<span class="severity-medium">🟡 MEDIUM</span>', unsafe_allow_html=True)
    elif severity == "low":
        st.markdown('<span class="severity-low">🟢 LOW</span>', unsafe_allow_html=True)
    else:
        st.markdown(f'<span class="severity-medium">⚪ {severity.upper()}</span>', unsafe_allow_html=True)


def render_confidence_bar(confidence: float):
    """
    Render a confidence score progress bar.
    
    Args:
        confidence: Confidence score (0.0 to 1.0)
    """
    confidence_percent = int(confidence * 100) if confidence else 0
    st.progress(confidence_percent / 100)
    st.caption(f"Confidence Score: {confidence_percent}%")


def render_sidebar():
    """
    Render the sidebar with past threats and statistics.
    """
    st.sidebar.title("📊 Dashboard")
    
    # Get vector store
    vector_store = get_vector_store()
    
    # Get statistics
    stats = vector_store.get_stats()
    
    # Display stats
    st.sidebar.metric("Total Analyzed", stats["total_reports"])
    st.sidebar.metric("High Severity", stats["high_severity_count"])
    
    st.sidebar.divider()
    
    # Display past threats
    st.sidebar.subheader("📜 Past Threats")
    
    past_reports = vector_store.get_all_reports()
    
    if past_reports:
        for report in past_reports[-10:]:  # Show last 10
            with st.sidebar.expander(
                f"{report.get('threat_id', 'Unknown')} - {report.get('severity', 'Unknown').upper()}"
            ):
                st.write(f"**Type:** {report.get('threat_type', 'Unknown')}")
                st.write(f"**Date:** {report.get('timestamp', 'Unknown')}")
                st.write(f"**Query:** {report.get('query', 'Unknown')}")
    else:
        st.sidebar.info("No past threats analyzed yet.")


def render_main_interface():
    """
    Render the main interface for threat analysis.
    """
    # Header
    st.markdown('<h1 class="main-header">🛡️ CyberSentinel Lite — AI Threat Analyzer</h1>', unsafe_allow_html=True)
    
    # Input section
    st.subheader("Analyze a Threat")
    
    col1, col2 = st.columns([4, 1])
    
    with col1:
        query = st.text_input(
            "Enter IP address, CVE ID, or threat keyword",
            placeholder="e.g., 192.168.1.1, CVE-2024-1234, or ransomware",
            key="query_input"
        )
    
    with col2:
        analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)
    
    # Examples
    st.caption("Examples: CVE-2024-1234 | 192.168.1.1 | ransomware | phishing | zero-day")
    
    # Analysis section
    if analyze_button and query:
        with st.spinner("🔄 Analyzing threat... This may take a moment."):
            try:
                # Get workflow and run analysis
                workflow = get_workflow()
                result = workflow.run(query)
                
                # Display results
                render_results(result)
                
            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")
                st.info("Please check your API keys in the .env file and try again.")


def render_results(result: dict):
    """
    Render the analysis results.
    
    Args:
        result: Workflow result containing the final report
    """
    report = result.get("final_report", {})
    
    if not report or "error" in report:
        st.error("❌ No report generated")
        if "error" in report:
            st.code(report["error"])
        return
    
    # Check if it's a direct answer
    if report.get("type") == "direct_answer":
        st.success("💬 Direct Answer")
        st.markdown(f"**{report.get('summary', '')}**")
        return
    
    # Threat ID and Timestamp
    col1, col2, col3 = st.columns([2, 2, 2])
    
    with col1:
        st.metric("Threat ID", report.get("threat_id", "Unknown"))
    
    with col2:
        st.metric("Threat Type", report.get("threat_type", "Unknown").replace("_", " ").title())
    
    with col3:
        st.metric("Timestamp", datetime.fromisoformat(report.get("timestamp", "")).strftime("%Y-%m-%d %H:%M") if report.get("timestamp") else "Unknown")
    
    st.divider()
    
    # Severity and Source
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.write("**Severity:**")
        render_severity_badge(report.get("severity", "Unknown"))
    
    with col2:
        st.write("**Source:**")
        st.markdown(f'<span class="source-tag">{report.get("source_used", "Unknown")}</span>', unsafe_allow_html=True)
    
    st.divider()
    
    # Summary
    st.subheader("📋 Summary")
    st.markdown(f'<div class="summary-card">{report.get("summary", "No summary available.")}</div>', unsafe_allow_html=True)
    
    # Confidence Score
    st.subheader("🎯 Confidence Score")
    render_confidence_bar(report.get("confidence_score", 0.0))
    
    st.divider()
    
    # Threat Details (Expandable)
    with st.expander("🔍 Threat Details"):
        # Affected Systems
        if report.get("affected_systems"):
            st.subheader("Affected Systems")
            for system in report["affected_systems"]:
                st.write(f"• {system}")
        
        # CVE References
        if report.get("cve_references"):
            st.subheader("CVE References")
            for cve in report["cve_references"]:
                st.write(f"• {cve}")
        
        # Indicators
        if report.get("indicators"):
            st.subheader("Indicators of Compromise (IOCs)")
            for indicator in report["indicators"]:
                st.write(f"• {indicator}")
    
    # Mitigation Steps
    if report.get("mitigation_steps"):
        st.subheader("🛡️ Mitigation Steps")
        for i, step in enumerate(report["mitigation_steps"], 1):
            st.markdown(f'<div class="mitigation-step"><strong>{i}.</strong> {step}</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # LangSmith Trace Link
    st.subheader("🔗 LangSmith Trace")
    if os.getenv("LANGCHAIN_TRACING_V2") == "true":
        langsmith_project = os.getenv("LANGCHAIN_PROJECT", "cybersentinel-lite")
        langsmith_url = f"https://smith.langchain.com/o/{os.getenv('LANGCHAIN_ORGANIZATION_ID', '')}/projects/p/{langsmith_project}"
        st.markdown(f"[View in LangSmith →]({langsmith_url})")
        st.caption("Make sure you're logged into LangSmith to view traces.")
    else:
        st.info("LangSmith tracing is not enabled. Set LANGCHAIN_TRACING_V2=true in .env to enable.")


def check_api_keys():
    """
    Check if required API keys are configured.
    """
    missing_keys = []
    
    if not os.getenv("GROQ_API_KEY"):
        missing_keys.append("GROQ_API_KEY")
    
    if not os.getenv("LANGCHAIN_API_KEY"):
        missing_keys.append("LANGCHAIN_API_KEY")
    
    if missing_keys:
        st.warning(f"⚠️ Missing API keys: {', '.join(missing_keys)}")
        st.info("Please add these keys to your .env file to use the application.")
        return False
    
    return True


def main():
    """
    Main application entry point.
    """
    # Check API keys
    if not check_api_keys():
        st.stop()
    
    # Render sidebar
    render_sidebar()
    
    # Render main interface
    render_main_interface()
    
    # Footer
    st.divider()
    st.caption("Built with LangGraph, LangChain, and Streamlit | CyberSentinel Lite v1.0")


if __name__ == "__main__":
    main()
