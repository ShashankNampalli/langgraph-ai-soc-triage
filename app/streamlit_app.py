"""Streamlit SOC analyst console for playbook triage."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any

# Repo root on path for Streamlit Cloud (`app/streamlit_app.py` entrypoint)
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from src.db import (
    alert_count,
    distinct_values,
    get_alert,
    get_triage_run,
    init_db,
    list_alerts,
    list_triage_runs,
    save_triage_run,
)
from src.graph import TriageState, get_interrupt_payload, invoke_triage, resume_triage
from src.scenarios import SAMPLE_ALERTS

st.set_page_config(
    page_title="LangGraph AI SOC Triage",
    page_icon="🛡️",
    layout="wide",
)


def _run_async(coro):
    return asyncio.run(coro)


def _severity_color(severity: str) -> str:
    return {
        "critical": "red",
        "high": "orange",
        "medium": "goldenrod",
        "low": "green",
        "info": "gray",
        "emergency": "red",
    }.get(severity.lower(), "blue")


def _render_classification(c: Any) -> None:
    if not c:
        return
    st.subheader("Classification")
    st.write(f"**Severity:** {c.severity.value.upper()}")
    st.write(f"**Category:** {c.category.value}")
    st.write(f"**Confidence:** {c.confidence:.0%}")
    st.write(c.reasoning)


def _render_investigation(inv: Any) -> None:
    if not inv:
        return
    st.subheader("Investigation")
    st.write(f"**Scope:** {inv.affected_scope}")
    st.write(f"**Attack vector:** {inv.attack_vector}")
    for f in inv.findings:
        st.write(f"- {f}")
    if inv.requires_escalation:
        st.error(f"Gate #1 — Escalation: {inv.escalation_reason}")


def _render_remediation(rem: Any) -> None:
    if not rem:
        return
    st.subheader("Remediation")
    st.write("**Immediate actions**")
    for a in rem.immediate_actions:
        st.write(f"- {a}")
    st.write("**Long-term fixes**")
    for a in rem.long_term_fixes:
        st.write(f"- {a}")
    if rem.requires_human_approval:
        st.warning(f"Gate #2 — Needs approval: {rem.approval_reason}")


def _render_result(result: dict) -> None:
    _render_classification(result.get("classification"))
    _render_investigation(result.get("investigation"))
    _render_remediation(result.get("remediation"))
    status = result.get("status", "unknown")
    st.info(f"**Status:** {status}")
    if result.get("human_decision"):
        st.write(result["human_decision"])


def page_alert_queue() -> None:
    st.header("Alert Queue")
    count = alert_count()
    if count == 0:
        st.warning(
            "No alerts in database. Run: `python scripts/ingest_alerts.py`"
        )
        return

    st.caption(f"{count:,} SIEM alerts loaded")

    col1, col2, col3 = st.columns(3)
    severities = ["all"] + distinct_values("severity")
    event_types = ["all"] + distinct_values("event_type")

    with col1:
        severity = st.selectbox("Severity", severities, key="q_sev")
    with col2:
        event_type = st.selectbox("Event type", event_types, key="q_type")
    with col3:
        search = st.text_input("Search", key="q_search")

    page = st.number_input("Page", min_value=1, value=1, step=1)
    page_size = 25
    offset = (page - 1) * page_size

    alerts = list_alerts(
        severity=severity,
        event_type=event_type,
        search=search or None,
        limit=page_size,
        offset=offset,
    )

    if not alerts:
        st.info("No alerts match filters.")
        return

    for row in alerts:
        with st.expander(
            f"[{row['severity']}] {row['title'][:80]} — {row['event_id'][:8]}..."
        ):
            st.write(row["description"][:500])
            st.caption(f"Source: {row['source']} | Type: {row['event_type']} | {row['timestamp']}")
            if st.button("Triage this alert", key=f"triage_{row['event_id']}"):
                st.session_state.selected_alert_id = row["event_id"]
                st.session_state.page = "Triage"
                st.rerun()


def page_curated() -> None:
    st.header("Curated Demo Scenarios")
    st.caption("Hand-crafted alerts designed to trigger HITL gates.")

    for i, alert in enumerate(SAMPLE_ALERTS):
        with st.expander(f"{alert.alert_id} — {alert.title}"):
            st.write(alert.description)
            if st.button("Triage", key=f"curated_{i}"):
                st.session_state.selected_alert = alert
                st.session_state.selected_alert_id = None
                st.session_state.page = "Triage"
                st.rerun()


def page_triage() -> None:
    st.header("Triage Run")

    alert = st.session_state.get("selected_alert")
    if alert is None and st.session_state.get("selected_alert_id"):
        alert = get_alert(st.session_state.selected_alert_id)

    if alert is None:
        st.info("Select an alert from the Alert Queue or Curated Demos tab.")
        return

    st.subheader(alert.title)
    st.write(alert.description)
    st.caption(f"ID: {alert.alert_id} | Source: {alert.source}")

    # Triage state machine for HITL
    if "triage_thread" not in st.session_state:
        st.session_state.triage_thread = None
    if "triage_result" not in st.session_state:
        st.session_state.triage_result = None
    if "triage_run_id" not in st.session_state:
        st.session_state.triage_run_id = None

    interrupt = get_interrupt_payload(st.session_state.triage_result or {})

    if interrupt:
        gate = interrupt.get("gate", "unknown")
        st.warning(f"Human approval required — Gate: **{gate}**")
        st.write(interrupt.get("message", ""))
        for reason in interrupt.get("reasons", []):
            st.write(f"- {reason}")
        _render_partial(st.session_state.triage_result)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Approve", type="primary"):
                st.session_state.triage_result = _run_async(
                    resume_triage(st.session_state.triage_thread, "approve")
                )
                if not get_interrupt_payload(st.session_state.triage_result):
                    _finish_run(alert, st.session_state.triage_result)
                st.rerun()
        with col2:
            if st.button("Reject"):
                st.session_state.triage_result = _run_async(
                    resume_triage(st.session_state.triage_thread, "reject")
                )
                if not get_interrupt_payload(st.session_state.triage_result):
                    _finish_run(alert, st.session_state.triage_result)
                st.rerun()
        return

    if st.session_state.triage_result:
        _render_result(st.session_state.triage_result)
        if st.button("Clear / new run"):
            st.session_state.triage_thread = None
            st.session_state.triage_result = None
            st.session_state.triage_run_id = None
            st.rerun()
        return

    if st.button("Run Triage Pipeline", type="primary"):
        thread_id = f"ui-{uuid.uuid4().hex[:12]}"
        run_id = uuid.uuid4().hex
        st.session_state.triage_thread = thread_id
        st.session_state.triage_run_id = run_id

        initial: TriageState = {
            "alert": alert,
            "classification": None,
            "investigation": None,
            "remediation": None,
            "human_decision": "",
            "status": "pending",
        }
        with st.spinner("Running classify -> investigate -> remediate..."):
            result = _run_async(invoke_triage(initial, thread_id))
        st.session_state.triage_result = result

        if not get_interrupt_payload(result):
            _finish_run(alert, result)
        st.rerun()


def _render_partial(result: dict) -> None:
    _render_classification(result.get("classification"))
    _render_investigation(result.get("investigation"))
    _render_remediation(result.get("remediation"))


def _finish_run(alert: Any, result: dict) -> None:
    save_triage_run(
        run_id=st.session_state.triage_run_id or uuid.uuid4().hex,
        thread_id=st.session_state.triage_thread or "",
        alert_id=alert.alert_id,
        status=result.get("status", "unknown"),
        human_decision=result.get("human_decision", ""),
        classification=result.get("classification"),
        investigation=result.get("investigation"),
        remediation=result.get("remediation"),
    )


def page_audit() -> None:
    st.header("Audit Log")
    runs = list_triage_runs(limit=100)
    if not runs:
        st.info("No triage runs yet.")
        return

    for run in runs:
        with st.expander(
            f"{run['created_at'][:19]} | {run['status']} | {run.get('title', run['alert_id'])[:60]}"
        ):
            st.write(f"Run ID: `{run['run_id']}`")
            st.write(f"Alert: `{run['alert_id']}` | Severity: {run.get('severity', 'n/a')}")
            st.write(run.get("human_decision", ""))
            detail = get_triage_run(run["run_id"])
            if detail:
                if detail.get("classification_json"):
                    st.json(detail["classification_json"])
                if detail.get("investigation_json"):
                    st.json(detail["investigation_json"])
                if detail.get("remediation_json"):
                    st.json(detail["remediation_json"])


def main() -> None:
    init_db()

    st.sidebar.title("LangGraph AI SOC Triage")
    page = st.sidebar.radio(
        "Navigation",
        ["Alert Queue", "Curated Demos", "Triage", "Audit Log"],
        index=["Alert Queue", "Curated Demos", "Triage", "Audit Log"].index(
            st.session_state.get("page", "Alert Queue")
        ),
    )
    st.session_state.page = page

    st.sidebar.divider()
    st.sidebar.metric("Alerts in DB", f"{alert_count():,}")

    if page == "Alert Queue":
        page_alert_queue()
    elif page == "Curated Demos":
        page_curated()
    elif page == "Triage":
        page_triage()
    else:
        page_audit()


if __name__ == "__main__":
    main()
