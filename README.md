# AI Firewall - Nova Hackathon 2025

Production-ready security layer for LLM applications.

## Features
- Real-time PII detection and redaction
- Secrets and confidential data protection
- Enterprise audit logging via Airia
- Seamless LLM integration with OpenRouter

## Setup
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration
Create `.env` file:
```
OPENROUTER_API_KEY=your_key
AIRIA_API_KEY=your_key
AIRIA_AGENT_ID=your_agent_id
AIRIA_API_URL=your_api_url
```

## Run
```bash
streamlit run app.py
```

## Tech Stack
- Streamlit (UI)
- OpenRouter (LLM)
- Airia (Security Logging)
- Python 3.11+