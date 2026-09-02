# LangGraph AI SOC Triage — Project Notes

## Overview

Multi-agent incident triage: classify → investigate → remediate, with human approval at two deterministic gates before high-risk remediation steps.

## Architecture

See `docs/SPEC.md` and the architecture diagrams in [README.md](README.md).

## Tech Stack

| Layer | Tool |
|-------|------|
| Orchestration | LangGraph |
| Structured outputs | Pydantic |
| LLM | DeepSeek API (default), Ollama optional |
| Playbooks | SQLite/JSON ingest, optional Qdrant RAG |
| UI | Streamlit analyst console |
| Persistence | SQLite alerts, playbooks, audit log |

## Data sources (Hugging Face)

| Purpose | Dataset |
|---------|---------|
| Playbook knowledge base | [darkknight25/Incident_Response_Playbook_Dataset](https://huggingface.co/datasets/darkknight25/Incident_Response_Playbook_Dataset) |
| Synthetic alert stream | [darkknight25/Advanced_SIEM_Dataset](https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset) |

```python
from datasets import load_dataset
playbooks = load_dataset("darkknight25/Incident_Response_Playbook_Dataset")
alerts = load_dataset("darkknight25/Advanced_SIEM_Dataset")
```

## Portfolio narrative

*"Built an AI multi-agent incident-response system with LangGraph implementing a Classify → Investigate → Remediate workflow, with human-in-the-loop approval gates before any disruptive remediation action."*
