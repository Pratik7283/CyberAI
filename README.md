# CyberSentinel — AI Threat Intelligence Platform

An AI-powered threat analysis system using LangGraph workflow orchestration with 3-tier RAG architecture (Adaptive, Corrective, Agentic) to classify security queries, retrieve threat intelligence from multiple APIs, and generate structured incident reports.

## Features

- **Adaptive RAG**: Intelligently routes simple questions to direct LLM answers and complex threats to full RAG pipeline
- **Corrective RAG**: Grades retrieved documents for relevance with fallback to NewsAPI when data is irrelevant
- **Agentic RAG**: LLM autonomously selects appropriate tools (NVD, AbuseIPDB, NewsAPI) based on query type
- **Intelligent Caching**: ChromaDB semantic search for past threats to avoid redundant API calls
- **Structured Outputs**: Pydantic models for type-safe LLM outputs
- **Comprehensive Evaluation**: Rule-based and integration testing for all components

## Tech Stack

- **Python** - Core language
- **LangGraph** - Workflow orchestration
- **Groq LLM** - Fast inference with LLaMA models
- **ChromaDB** - Vector database for semantic search
- **Streamlit** - Web UI
- **RAG** - Retrieval Augmented Generation
- **Pydantic** - Data validation
- **NVD API** - CVE vulnerability data
- **NewsAPI** - Threat news
- **AbuseIPDB** - IP reputation

## Project Structure

```
CyberSecurityAI/
├── agents/              # LLM agents (investigator, responder)
├── graph/               # LangGraph workflow orchestration
├── rag/                 # RAG components (adaptive router, corrective RAG)
├── tools/               # API integrations (NVD, AbuseIPDB, NewsAPI)
├── memory/              # Vector store management
├── schemas/             # Pydantic models
├── ui/                  # Streamlit web interface
├── evaluation/          # LLM evaluation scripts
└── requirements.txt     # Dependencies
```

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file with your API keys:

```env
GROQ_API_KEY=your_groq_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
NEWS_API_KEY=your_news_api_key
LANGCHAIN_API_KEY=your_langchain_api_key
```

## Usage

### Run the Web UI

```bash
streamlit run ui/app.py
```

### Run Evaluations

```bash
# Router evaluation
python evaluation/test_router.py

# Investigator evaluation
python evaluation/test_investigator.py

# Responder evaluation
python evaluation/test_responder.py

# Grader evaluation
python evaluation/test_grader.py

# Workflow evaluation
python evaluation/test_workflow.py
```

## Evaluation Results

- **Router**: 100% accuracy (7/7 tests)
- **Investigator**: 100% extraction accuracy
- **Responder**: 100% severity classification, 80% overall
- **Grader**: 100% accuracy (6/6 tests)
- **Workflow**: 100% accuracy (4/4 tests)

## Example Queries

- CVE analysis: `CVE-2024-3094`
- IP reputation: `8.8.8.8`
- Threat keywords: `ransomware`, `phishing`
- Conceptual questions: `What is a DDoS attack?`

## License

MIT License
