# Project Spec — LangGraph AI SOC Triage

> **Implemented:** DeepSeek API default LLM, LangGraph HITL gates, playbook RAG (Qdrant optional), Streamlit console, SQLite audit log, 6 demo scenarios. See [README.md](../README.md) for setup.

## Overview

A stateful multi-agent system that walks through incident-response runbook steps (classify → investigate → remediate), pausing for human approval at high-risk steps before continuing to remediation or execution.

**Why this matters:** Human-in-the-loop control over destructive actions is what separates a demo from something a security team would trust. Gates are code-enforced via LangGraph `interrupt()`, not LLM discretion.

## Architecture

```
        New Alert / Incident Trigger
                    │
                    ▼
        ┌──────────────────────┐
        │   Classify Agent       │
        └──────────┬───────────┘
                    ▼
        ┌──────────────────────┐
        │  Investigate Agent     │
        └──────────┬───────────┘
                    ▼
              Active breach?
              ┌────┴────┐
             Yes         No
              │           │
              ▼           ▼
      ┌───────────────┐
      │ HUMAN APPROVAL │──── Gate #1
      │    GATE #1     │
      └───────┬────────┘
              ▼
        ┌──────────────────────┐
        │   Remediate Agent      │
        └──────────┬───────────┘
                    ▼
              Disruptive action?
              ┌────┴────┐
             Yes         No
              │           │
              ▼           ▼
      ┌───────────────┐
      │ HUMAN APPROVAL │──── Gate #2
      │    GATE #2     │
      └───────┬────────┘
              ▼
        ┌──────────────────────┐
        │   Execute + Log        │
        └──────────────────────┘
```

## Tech Stack

| Layer | Tool |
|-------|------|
| Orchestration | LangGraph `StateGraph` with conditional routing and HITL interrupts |
| Structured outputs | Pydantic — Alert, Classification, Investigation, Remediation |
| Retrieval | Playbook ingest (SQLite/JSON), optional LlamaIndex + Qdrant RAG |
| Safety | Regex guardrails on alert input and remediation output |
| Human-in-the-loop | CLI, Streamlit approve/reject, optional Slack webhook notify |
| UI | Streamlit SOC analyst console |

## Portfolio narrative

*"Built an AI multi-agent incident-response system with LangGraph implementing a Classify → Investigate → Remediate workflow, with human-in-the-loop approval gates before any disruptive remediation action. All agent decisions produce typed, structured outputs for downstream automation and auditability."*

## Data sources

See [README.md](../README.md#data-sources) for Hugging Face datasets used in this project.
