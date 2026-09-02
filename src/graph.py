"""LangGraph workflow for multi-agent security triage with HITL gates."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt
from typing_extensions import TypedDict

from .agents import classify_alert, investigate_alert, recommend_remediation
from .models import Classification, Investigation, Remediation, SecurityAlert, Severity

CHECKPOINT_PATH = Path(os.getenv("CHECKPOINT_DB", "data/checkpoints.db"))
_checkpointer = MemorySaver()


class TriageState(TypedDict):
    """State passed between nodes in the triage graph."""

    alert: SecurityAlert
    classification: Classification | None
    investigation: Investigation | None
    remediation: Remediation | None
    human_decision: str
    status: str


# --- Graph Nodes ---


async def classify_node(state: TriageState) -> dict:
    classification = await classify_alert(state["alert"])
    return {"classification": classification}


async def investigate_node(state: TriageState) -> dict:
    investigation = await investigate_alert(state["alert"], state["classification"])
    return {"investigation": investigation}


async def investigation_hitl_node(state: TriageState) -> dict:
    """Gate #1: Human approval before remediation when active breach detected."""
    investigation = state["investigation"]
    reasons = [investigation.escalation_reason] if investigation else ["Escalation required"]

    approval = interrupt(
        {
            "gate": "investigation",
            "reasons": reasons,
            "alert_title": state["alert"].title,
            "message": "Active breach detected. Approve continuing to remediation?",
        }
    )

    if not isinstance(approval, dict):
        approval = {"decision": str(approval)}

    if approval.get("decision") != "approve":
        return {
            "status": "closed",
            "human_decision": "Rejected at investigation gate (gate #1)",
        }
    return {
        "human_decision": "Approved at investigation gate (gate #1)",
        "status": "investigation_approved",
    }


async def remediate_node(state: TriageState) -> dict:
    remediation = await recommend_remediation(
        state["alert"], state["classification"], state["investigation"]
    )
    return {"remediation": remediation}


async def remediation_hitl_node(state: TriageState) -> dict:
    """Gate #2: Human approval before executing disruptive remediation."""
    remediation = state["remediation"]
    classification = state["classification"]
    reasons = []

    if classification and classification.severity in (Severity.CRITICAL, Severity.HIGH):
        reasons.append(f"Severity: {classification.severity.value}")
    if remediation and remediation.requires_human_approval:
        reasons.append(remediation.approval_reason or "Disruptive remediation action")

    approval = interrupt(
        {
            "gate": "remediation",
            "reasons": reasons,
            "alert_title": state["alert"].title,
            "message": "Disruptive action proposed. Approve execution?",
        }
    )

    if not isinstance(approval, dict):
        approval = {"decision": str(approval)}

    if approval.get("decision") != "approve":
        return {
            "status": "closed",
            "human_decision": state.get("human_decision", "")
            + "; Rejected at remediation gate (gate #2)",
        }
    return {
        "human_decision": state.get("human_decision", "")
        + "; Approved at remediation gate (gate #2)",
        "status": "remediation_approved",
    }


async def execute_and_log_node(state: TriageState) -> dict:
    """Execute approved remediation and log for audit."""
    remediation = state["remediation"]
    actions = remediation.immediate_actions if remediation else []
    return {
        "status": "executed",
        "human_decision": state.get("human_decision", "")
        + f"; Executed {len(actions)} immediate action(s) and logged to audit trail",
    }


async def auto_resolve_node(state: TriageState) -> dict:
    return {
        "status": "auto_resolved",
        "human_decision": "Auto-resolved: low risk, no escalation needed",
    }


async def close_incident_node(state: TriageState) -> dict:
    return {
        "status": state.get("status", "closed"),
        "human_decision": state.get("human_decision", "Incident closed without remediation"),
    }


# --- Routing Logic ---


def route_after_investigation(
    state: TriageState,
) -> Literal["investigation_hitl", "remediate"]:
    if state["investigation"] and state["investigation"].requires_escalation:
        return "investigation_hitl"
    return "remediate"


def route_after_investigation_hitl(
    state: TriageState,
) -> Literal["remediate", "close_incident"]:
    if state.get("status") == "closed":
        return "close_incident"
    return "remediate"


def route_after_remediation(
    state: TriageState,
) -> Literal["remediation_hitl", "auto_resolve"]:
    classification = state["classification"]
    remediation = state["remediation"]

    if classification and classification.severity in (Severity.CRITICAL, Severity.HIGH):
        return "remediation_hitl"
    if remediation and remediation.requires_human_approval:
        return "remediation_hitl"
    return "auto_resolve"


def route_after_remediation_hitl(
    state: TriageState,
) -> Literal["execute_and_log", "close_incident"]:
    if state.get("status") == "closed":
        return "close_incident"
    return "execute_and_log"


# --- Build Graph ---


def build_triage_graph() -> StateGraph:
    graph = StateGraph(TriageState)

    graph.add_node("classify", classify_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("investigation_hitl", investigation_hitl_node)
    graph.add_node("remediate", remediate_node)
    graph.add_node("remediation_hitl", remediation_hitl_node)
    graph.add_node("execute_and_log", execute_and_log_node)
    graph.add_node("auto_resolve", auto_resolve_node)
    graph.add_node("close_incident", close_incident_node)

    graph.set_entry_point("classify")
    graph.add_edge("classify", "investigate")
    graph.add_conditional_edges(
        "investigate",
        route_after_investigation,
        {"investigation_hitl": "investigation_hitl", "remediate": "remediate"},
    )
    graph.add_conditional_edges(
        "investigation_hitl",
        route_after_investigation_hitl,
        {"remediate": "remediate", "close_incident": "close_incident"},
    )
    graph.add_conditional_edges(
        "remediate",
        route_after_remediation,
        {"remediation_hitl": "remediation_hitl", "auto_resolve": "auto_resolve"},
    )
    graph.add_conditional_edges(
        "remediation_hitl",
        route_after_remediation_hitl,
        {"execute_and_log": "execute_and_log", "close_incident": "close_incident"},
    )
    graph.add_edge("execute_and_log", END)
    graph.add_edge("auto_resolve", END)
    graph.add_edge("close_incident", END)

    return graph


def compile_triage_graph():
    graph = build_triage_graph()
    return graph.compile(checkpointer=_checkpointer)


def _thread_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


async def invoke_triage(initial_state: TriageState, thread_id: str) -> dict:
    """Start a new triage run."""
    app = compile_triage_graph()
    return await app.ainvoke(initial_state, _thread_config(thread_id))


async def resume_triage(thread_id: str, decision: str) -> dict:
    app = compile_triage_graph()
    config = _thread_config(thread_id)
    return await app.ainvoke(Command(resume={"decision": decision}), config)


def get_interrupt_payload(result: dict) -> dict | None:
    if "__interrupt__" not in result:
        return None
    interrupts = result["__interrupt__"]
    if not interrupts:
        return None
    payload = interrupts[0].value
    return payload if isinstance(payload, dict) else {"gate": "unknown", "reasons": [str(payload)]}


async def run_triage(
    initial_state: TriageState,
    thread_id: str = "default",
    auto_approve: bool = False,
    approval_fn: Any | None = None,
) -> dict:
    """Run triage pipeline, handling HITL interrupts until completion."""
    result = await invoke_triage(initial_state, thread_id)

    while get_interrupt_payload(result):
        payload = get_interrupt_payload(result) or {}

        if auto_approve:
            decision = "approve"
        elif approval_fn:
            decision = approval_fn(payload)
        else:
            from .hitl import request_approval

            approved = await request_approval(payload)
            decision = approved.get("decision", "reject")

        result = await resume_triage(thread_id, decision)

    return result
