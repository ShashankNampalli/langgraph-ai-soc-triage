"""Streamlit SOC analyst console for playbook triage."""

from __future__ import annotations

import asyncio
import html
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
    db_stats,
    distinct_values,
    get_alert,
    get_triage_run,
    init_db,
    list_alerts,
    list_triage_runs,
    load_all_playbooks,
    playbook_count,
    save_triage_run,
    severity_breakdown,
)
from src.graph import TriageState, get_interrupt_payload, invoke_triage, resume_triage
from src.paths import default_db_path
from src.scenarios import SAMPLE_ALERTS, SCENARIO_EXPECTATIONS
from src.seed import database_ready, seed

st.set_page_config(
    page_title="SOC Triage · Analyst Console",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",  # collapse via << on the sidebar edge
)

APP_NAME = "SOC Triage"
APP_TAGLINE = "Playbook Execution Agent"
AUTHOR_NAME = "Shashank Nampalli"

CONSOLE_VIEWS = [
    "Alert Queue",
    "Curated Demos",
    "Active Triage",
    "Playbooks",
    "Audit Log",
]


def inject_styles() -> None:
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500;600&family=Syne:wght@700;800&display=swap');

:root {
  --bg: #0c1118;
  --panel: #141b24;
  --panel-2: #1a2330;
  --line: #2a3645;
  --ink: #e8eef5;
  --muted: #8b9aab;
  --teal: #2dd4bf;
  --teal-dim: rgba(45, 212, 191, 0.14);
  --crit: #f07167;
  --high: #f0a05a;
  --med: #e6c35c;
  --low: #6ecf9b;
  --info: #7aa2ff;
}

html, body, [class*="css"] {
  font-family: "IBM Plex Sans", sans-serif;
  color: var(--ink);
}

.stApp {
  background:
    radial-gradient(900px 420px at 0% 0%, rgba(45, 212, 191, 0.08), transparent 55%),
    radial-gradient(700px 360px at 100% 0%, rgba(240, 113, 103, 0.06), transparent 50%),
    linear-gradient(180deg, #0a0f15 0%, #0c1118 100%);
}

[data-testid="stAppViewContainer"] > .main {
  background: transparent;
}

#MainMenu { visibility: hidden; }
header a[href*="streamlit.io"],
footer a[href*="streamlit.io"] {
  display: none !important;
}

section[data-testid="stSidebar"] {
  background: #0a1017 !important;
  border-right: 1px solid var(--line);
}

section[data-testid="stSidebar"] * {
  color: var(--ink) !important;
}

section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
  color: var(--muted) !important;
}

.console-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.85rem 1.1rem;
  margin-bottom: 0.85rem;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: linear-gradient(135deg, #121925 0%, #0f1620 100%);
}

.console-brand {
  font-family: "Syne", sans-serif;
  font-weight: 800;
  font-size: 1.45rem;
  letter-spacing: -0.03em;
  margin: 0;
  color: var(--ink);
  line-height: 1.1;
}

.console-brand span { color: var(--teal); }

.console-sub {
  margin: 0.2rem 0 0 0;
  font-size: 0.78rem;
  color: var(--muted);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.live-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.28rem 0.65rem;
  border-radius: 999px;
  border: 1px solid rgba(45, 212, 191, 0.35);
  background: var(--teal-dim);
  color: var(--teal);
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.live-pill .dot {
  width: 0.45rem;
  height: 0.45rem;
  border-radius: 50%;
  background: var(--teal);
  box-shadow: 0 0 0 3px rgba(45, 212, 191, 0.2);
  animation: blink 1.8s ease-in-out infinite;
}

@keyframes blink {
  0%, 100% { opacity: 0.45; }
  50% { opacity: 1; }
}

.kpi-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 0.55rem;
  margin-bottom: 0.95rem;
}

@media (max-width: 1100px) {
  .kpi-row { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}

.kpi {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.7rem 0.8rem;
  border-top: 3px solid var(--line);
}

.kpi.crit { border-top-color: var(--crit); }
.kpi.high { border-top-color: var(--high); }
.kpi.med { border-top-color: var(--med); }
.kpi.low { border-top-color: var(--low); }
.kpi.teal { border-top-color: var(--teal); }
.kpi.info { border-top-color: var(--info); }

.kpi .label {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--muted);
  font-weight: 600;
}

.kpi .value {
  margin-top: 0.2rem;
  font-family: "IBM Plex Mono", monospace;
  font-size: 1.35rem;
  font-weight: 600;
  color: var(--ink);
  line-height: 1.1;
}

.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.9rem 1rem;
  margin-bottom: 0.75rem;
}

.panel h3, .panel h4 {
  font-family: "Syne", sans-serif;
  margin: 0 0 0.55rem 0;
  letter-spacing: -0.02em;
  color: var(--ink);
}

.section-title {
  font-family: "Syne", sans-serif;
  font-size: 1.25rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin: 0 0 0.25rem 0;
  color: var(--ink);
}

.section-hint {
  color: var(--muted);
  margin: 0 0 0.85rem 0;
  font-size: 0.9rem;
}

.sev-chip {
  display: inline-block;
  padding: 0.12rem 0.45rem;
  border-radius: 4px;
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.sev-chip.critical, .sev-chip.emergency { background: rgba(240,113,103,0.18); color: var(--crit); }
.sev-chip.high { background: rgba(240,160,90,0.18); color: var(--high); }
.sev-chip.medium { background: rgba(230,195,92,0.16); color: var(--med); }
.sev-chip.low { background: rgba(110,207,155,0.16); color: var(--low); }
.sev-chip.info, .sev-chip.demo { background: rgba(122,162,255,0.16); color: var(--info); }

.alert-card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 4px solid var(--line);
  border-radius: 10px;
  padding: 0.75rem 0.9rem;
  margin-bottom: 0.55rem;
}

.alert-card.critical, .alert-card.emergency { border-left-color: var(--crit); }
.alert-card.high { border-left-color: var(--high); }
.alert-card.medium { border-left-color: var(--med); }
.alert-card.low { border-left-color: var(--low); }
.alert-card.info, .alert-card.demo { border-left-color: var(--info); }

.alert-card .meta {
  color: var(--muted);
  font-size: 0.78rem;
  font-family: "IBM Plex Mono", monospace;
}

.alert-card .title {
  margin: 0.25rem 0 0.35rem 0;
  font-weight: 600;
  color: var(--ink);
  font-size: 0.98rem;
}

.alert-card .desc {
  margin: 0;
  color: #b7c3d1;
  font-size: 0.88rem;
  line-height: 1.4;
}

.response-section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.9rem 1rem;
  margin-bottom: 0.7rem;
  color: var(--ink);
}

.response-section h4 {
  font-family: "Syne", sans-serif;
  margin: 0 0 0.55rem 0;
  color: var(--ink);
}

.response-section p, .response-section li {
  color: #c5d0dc;
}

.arch-intro {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 1.05rem 1.15rem;
  margin-bottom: 1rem;
}

.arch-intro h3 {
  font-family: "Syne", sans-serif;
  margin: 0 0 0.5rem 0;
  color: var(--ink);
}

.arch-intro p {
  margin: 0 0 0.7rem 0;
  color: var(--muted);
  line-height: 1.5;
}

.dag-board {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 1rem;
  margin-bottom: 0.9rem;
}

.dag-board h4 {
  font-family: "Syne", sans-serif;
  margin: 0 0 0.85rem 0;
  color: var(--ink);
}

.dag-row {
  display: flex;
  justify-content: center;
  align-items: stretch;
  flex-wrap: wrap;
  gap: 0.65rem;
  margin: 0.3rem 0;
}

.dag-node {
  min-width: 130px;
  max-width: 210px;
  padding: 0.65rem 0.75rem;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--panel-2);
  text-align: center;
}

.dag-node .title {
  font-family: "IBM Plex Sans", sans-serif;
  font-weight: 700;
  font-size: 0.88rem;
  color: var(--ink);
}

.dag-node .sub {
  margin-top: 0.2rem;
  font-size: 0.72rem;
  color: var(--muted);
}

.dag-node.signal {
  background: rgba(45, 212, 191, 0.1);
  border-color: rgba(45, 212, 191, 0.35);
}

.dag-node.alert {
  background: rgba(240, 113, 103, 0.1);
  border-color: rgba(240, 113, 103, 0.35);
}

.dag-node.asphalt {
  background: #0a1017;
  border-color: #334155;
}

.dag-arrow {
  text-align: center;
  color: var(--muted);
  font-weight: 700;
  letter-spacing: 0.08em;
}

.dag-label {
  display: inline-block;
  margin-left: 0.25rem;
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
  font-size: 0.68rem;
  font-weight: 700;
  background: rgba(255,255,255,0.06);
  color: var(--muted);
}

button[data-baseweb="tab"] {
  font-family: "Syne", sans-serif !important;
  font-weight: 700 !important;
  color: var(--muted) !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
  color: var(--teal) !important;
}

.stButton > button {
  border-radius: 8px !important;
  border: 1px solid var(--line) !important;
  background: var(--panel-2) !important;
  color: var(--ink) !important;
  font-weight: 600 !important;
}

.stButton > button:hover {
  border-color: var(--teal) !important;
  color: var(--teal) !important;
}

button[kind="primary"],
.stButton > button[kind="primary"] {
  background: var(--teal) !important;
  border-color: var(--teal) !important;
  color: #042f2e !important;
  font-weight: 700 !important;
}

div[data-testid="stExpander"] {
  background: var(--panel) !important;
  border: 1px solid var(--line) !important;
  border-radius: 10px !important;
}

div[data-testid="stExpander"] details summary,
div[data-testid="stExpander"] details summary p,
div[data-testid="stExpander"] [data-testid="stMarkdownContainer"] p,
div[data-testid="stExpander"] [data-testid="stMarkdownContainer"] li {
  color: var(--ink) !important;
}

[data-testid="stDataFrame"] {
  border: 1px solid var(--line);
  border-radius: 10px;
  overflow: hidden;
}

.stSelectbox label, .stTextInput label, .stNumberInput label {
  color: var(--muted) !important;
}

.author-line {
  margin-top: 0.35rem;
  color: var(--muted);
  font-size: 0.8rem;
}
</style>
        """,
        unsafe_allow_html=True,
    )


def ensure_session() -> None:
    defaults = {
        "console_view": "Alert Queue",
        "selected_alert": None,
        "selected_alert_id": None,
        "triage_thread": None,
        "triage_result": None,
        "triage_run_id": None,
        "queue_selected_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def ensure_database() -> None:
    path = default_db_path()
    if database_ready(path):
        init_db()
        return
    with st.spinner("First run: seeding playbooks and curated alerts into SQLite…"):
        try:
            seed(path)
            st.toast("Sample database ready.", icon="✅")
        except Exception as exc:
            st.error(
                f"Could not create the SQLite database automatically: {exc}. "
                "Ensure data/playbooks.json is present, or run `python -m src.seed`."
            )


def _run_async(coro):
    return asyncio.run(coro)


def _sev_count(breakdown: dict[str, int], *keys: str) -> int:
    return sum(breakdown.get(k, 0) for k in keys)


def _sentence_case(text: str) -> str:
    """Normalize labels like 'firewall alert' / 'CLOUD' → sentence case."""
    value = (text or "").strip().replace("_", " ")
    if not value:
        return "—"
    lower = value.lower()
    return lower[:1].upper() + lower[1:]


def render_header() -> None:
    """App header — always above Analyst Console / Tech Architecture tabs."""
    st.markdown(
        f"""
<div class="console-bar">
  <div>
    <p class="console-brand">SOC <span>Triage</span></p>
    <p class="console-sub">{html.escape(APP_TAGLINE)}</p>
  </div>
  <div class="live-pill"><span class="dot"></span>Queue live</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar() -> str:
    st.sidebar.markdown("### Analyst views")
    st.sidebar.caption("Collapse sidebar with « on the edge")
    current = st.session_state.get("console_view", "Alert Queue")
    if current not in CONSOLE_VIEWS:
        current = "Alert Queue"
    view = st.sidebar.radio(
        "Views",
        CONSOLE_VIEWS,
        index=CONSOLE_VIEWS.index(current),
        label_visibility="collapsed",
    )
    st.session_state.console_view = view

    st.sidebar.divider()
    st.sidebar.markdown("### Database")
    db_path = default_db_path()
    ready = database_ready(db_path)
    status_color = "var(--teal)" if ready else "var(--crit)"
    status_label = "Ready" if ready else "Not ready"
    size_kb = db_path.stat().st_size / 1024 if db_path.exists() else 0.0
    st.sidebar.markdown(
        f"""
<div class="panel" style="padding:0.7rem 0.75rem;margin-bottom:0.55rem">
  <div style="display:flex;align-items:center;gap:0.4rem;margin-bottom:0.45rem">
    <span style="width:0.45rem;height:0.45rem;border-radius:50%;background:{status_color};
      box-shadow:0 0 0 3px rgba(45,212,191,0.15)"></span>
    <strong style="font-size:0.85rem">SQLite · {status_label}</strong>
  </div>
  <div style="font-size:0.72rem;color:var(--muted);font-family:IBM Plex Mono,monospace;
    word-break:break-all;line-height:1.35">{html.escape(str(db_path.name))}
    · {size_kb:,.1f} KB</div>
</div>
        """,
        unsafe_allow_html=True,
    )

    stats = db_stats()
    sev = severity_breakdown()
    critical = _sev_count(sev, "critical", "emergency")
    high = _sev_count(sev, "high")
    medium = _sev_count(sev, "medium")
    low = _sev_count(sev, "low", "info", "demo")
    st.sidebar.markdown("**Metrics**")
    m1, m2 = st.sidebar.columns(2)
    m1.metric("Alerts", f"{stats['alerts']:,}")
    m2.metric("Playbooks", f"{stats['playbooks']:,}")
    m3, m4 = st.sidebar.columns(2)
    m3.metric("Runs", f"{stats['runs']:,}")
    m4.metric("Demos", f"{len(SAMPLE_ALERTS)}")
    s1, s2 = st.sidebar.columns(2)
    s1.metric("Critical", f"{critical:,}")
    s2.metric("High", f"{high:,}")
    s3, s4 = st.sidebar.columns(2)
    s3.metric("Medium", f"{medium:,}")
    s4.metric("Low / other", f"{low:,}")

    st.sidebar.divider()
    st.sidebar.markdown("### Jump to demo")
    for i, alert in enumerate(SAMPLE_ALERTS):
        expect = SCENARIO_EXPECTATIONS.get(alert.alert_id, {})
        gates = []
        if expect.get("gate1"):
            gates.append("G1")
        if expect.get("gate2"):
            gates.append("G2")
        gate_tag = f" · {'/'.join(gates)}" if gates else " · auto"
        label = f"{alert.alert_id[-4:]}{gate_tag}"
        if st.sidebar.button(label, key=f"side_demo_{i}", use_container_width=True):
            _select_curated(alert)
    st.sidebar.caption("G1/G2 = HITL gates expected in offline mode")
    return view


def _select_curated(alert: Any) -> None:
    st.session_state.selected_alert = alert
    st.session_state.selected_alert_id = None
    st.session_state.triage_thread = None
    st.session_state.triage_result = None
    st.session_state.triage_run_id = None
    st.session_state.console_view = "Active Triage"
    st.rerun()


def _go_triage_from_queue(event_id: str) -> None:
    st.session_state.selected_alert_id = event_id
    st.session_state.selected_alert = None
    st.session_state.triage_thread = None
    st.session_state.triage_result = None
    st.session_state.triage_run_id = None
    st.session_state.console_view = "Active Triage"
    st.rerun()


def _section_header(title: str, hint: str = "") -> None:
    hint_html = f'<p class="section-hint">{html.escape(hint)}</p>' if hint else ""
    st.markdown(
        f'<h2 class="section-title">{html.escape(title)}</h2>{hint_html}',
        unsafe_allow_html=True,
    )


def _sev_chip(severity: str) -> str:
    sev = (severity or "info").lower()
    return f'<span class="sev-chip {html.escape(sev)}">{html.escape(sev)}</span>'


def _render_classification(c: Any) -> None:
    if not c:
        return
    st.markdown(
        f"""
<div class="response-section">
  <h4>Classification</h4>
  {_sev_chip(c.severity.value)}
  <p><strong>Category:</strong> {html.escape(c.category.value)} ·
     <strong>Confidence:</strong> {c.confidence:.0%}</p>
  <p>{html.escape(c.reasoning)}</p>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_investigation(inv: Any) -> None:
    if not inv:
        return
    findings = "".join(f"<li>{html.escape(f)}</li>" for f in inv.findings)
    escalate = ""
    if inv.requires_escalation:
        escalate = (
            f'<p style="color:var(--crit);font-weight:600">'
            f"Gate #1 — Escalation: {html.escape(inv.escalation_reason or '')}</p>"
        )
    st.markdown(
        f"""
<div class="response-section">
  <h4>Investigation</h4>
  <p><strong>Scope:</strong> {html.escape(inv.affected_scope)}</p>
  <p><strong>Attack vector:</strong> {html.escape(inv.attack_vector)}</p>
  <ul>{findings}</ul>
  {escalate}
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_remediation(rem: Any) -> None:
    if not rem:
        return
    immediate = "".join(f"<li>{html.escape(a)}</li>" for a in rem.immediate_actions)
    long_term = "".join(f"<li>{html.escape(a)}</li>" for a in rem.long_term_fixes)
    approval = ""
    if rem.requires_human_approval:
        approval = (
            f'<p style="color:var(--crit);font-weight:600">'
            f"Gate #2 — Needs approval: {html.escape(rem.approval_reason or '')}</p>"
        )
    st.markdown(
        f"""
<div class="response-section">
  <h4>Remediation</h4>
  <p><strong>Immediate actions</strong></p>
  <ul>{immediate}</ul>
  <p><strong>Long-term fixes</strong></p>
  <ul>{long_term}</ul>
  {approval}
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_result(result: dict) -> None:
    _render_classification(result.get("classification"))
    _render_investigation(result.get("investigation"))
    _render_remediation(result.get("remediation"))
    status = result.get("status", "unknown")
    decision = html.escape(str(result.get("human_decision") or ""))
    st.markdown(
        f"""
<div class="response-section">
  <h4>Disposition</h4>
  <p><strong>{html.escape(str(status))}</strong></p>
  <p>{decision}</p>
</div>
        """,
        unsafe_allow_html=True,
    )


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


def page_alert_queue() -> None:
    _section_header(
        "Alert Queue",
        "Filter the live SIEM queue, then hit Triage on any row to open Active Triage.",
    )
    count = alert_count()
    if count == 0:
        st.warning(
            "No alerts in database. Run `python -m src.seed` or "
            "`python scripts/ingest_alerts.py`."
        )
        return

    if "q_size" not in st.session_state:
        st.session_state.q_size = 25
    if "q_page" not in st.session_state:
        st.session_state.q_page = 1

    c1, c2, c3 = st.columns([1.2, 1.4, 2.0])
    severities = ["all"] + distinct_values("severity")
    event_types = ["all"] + distinct_values("event_type")
    with c1:
        severity = st.selectbox("Severity", severities, key="q_sev")
    with c2:
        event_type = st.selectbox("Event type", event_types, key="q_type")
    with c3:
        search = st.text_input("Search title / id / description", key="q_search")

    page_size = int(st.session_state.q_size)
    page_num = int(st.session_state.q_page)
    offset = (page_num - 1) * page_size

    alerts = list_alerts(
        severity=severity,
        event_type=event_type,
        search=search or None,
        limit=page_size,
        offset=offset,
    )
    if not alerts and page_num > 1:
        st.session_state.q_page = 1
        st.rerun()
    if not alerts:
        st.info("No alerts match filters.")
        return

    # Column headers (Streamlit dataframe can't host per-row buttons)
    hdr = st.columns([0.75, 2.2, 1.8, 0.9, 1.15, 1.1, 0.75])
    headers = ["Severity", "ID", "Alert", "Type", "Source", "Time", ""]
    for col, label in zip(hdr, headers):
        col.markdown(f"**{label}**")

    for row in alerts:
        sev = (row.get("severity") or "info").lower()
        title = _sentence_case(row.get("title") or "untitled alert")[:80]
        event_type_val = _sentence_case(row.get("event_type") or "")
        source = row.get("source") or "—"
        ts = (row.get("timestamp") or "")[:19] or "—"
        eid = row.get("event_id") or ""

        cols = st.columns([0.75, 2.2, 1.8, 0.9, 1.15, 1.1, 0.75])
        with cols[0]:
            st.markdown(_sev_chip(sev), unsafe_allow_html=True)
        with cols[1]:
            st.markdown(
                f"<div style='color:var(--muted);font-size:0.72rem;line-height:1.25;"
                f"font-family:IBM Plex Mono,ui-monospace,monospace;"
                f"word-break:break-all'>{html.escape(eid)}</div>",
                unsafe_allow_html=True,
            )
        with cols[2]:
            st.markdown(f"**{html.escape(title)}**")
        with cols[3]:
            st.caption(event_type_val)
        with cols[4]:
            st.caption(source)
        with cols[5]:
            st.caption(ts)
        with cols[6]:
            if st.button("Triage", key=f"triage_row_{eid}", use_container_width=True):
                _go_triage_from_queue(eid)

    total_pages = max(1, (count + page_size - 1) // page_size)
    if page_num > total_pages:
        st.session_state.q_page = total_pages
        st.rerun()

    st.divider()
    p1, p2, p3 = st.columns([1.2, 1.2, 2.0])
    with p1:
        st.selectbox("Page size", [25, 50, 100], key="q_size")
    with p2:
        st.number_input(
            "Page",
            min_value=1,
            max_value=total_pages,
            step=1,
            key="q_page",
        )
    with p3:
        st.caption(
            f"Showing {len(alerts)} of {count:,} alerts · "
            f"page {st.session_state.q_page} of {total_pages}"
        )


def page_curated() -> None:
    _section_header(
        "Curated Demo Scenarios",
        "Enterprise alerts designed to exercise HITL Gate #1 / Gate #2.",
    )
    for i, alert in enumerate(SAMPLE_ALERTS):
        expect = SCENARIO_EXPECTATIONS.get(alert.alert_id, {})
        g1 = "YES" if expect.get("gate1") else "no"
        g2 = "YES" if expect.get("gate2") else "no"
        st.markdown(
            f"""
<div class="alert-card high">
  <div class="meta">{html.escape(alert.alert_id)} · {html.escape(alert.source)} · Gate1 {g1} · Gate2 {g2}</div>
  <p class="title">{html.escape(alert.title)}</p>
  <p class="desc">{html.escape(alert.description[:280])}{"…" if len(alert.description) > 280 else ""}</p>
</div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Run triage", key=f"curated_{i}"):
            _select_curated(alert)


def page_triage() -> None:
    _section_header(
        "Active Triage",
        "Classify → investigate → remediate. Approve or reject when a HITL gate fires.",
    )

    alert = st.session_state.get("selected_alert")
    if alert is None and st.session_state.get("selected_alert_id"):
        alert = get_alert(st.session_state.selected_alert_id)

    if alert is None:
        st.info("Select an alert from Alert Queue, Curated Demos, or the sidebar.")
        return

    st.markdown(
        f"""
<div class="alert-card high">
  <div class="meta">{html.escape(alert.alert_id)} · {html.escape(alert.source)}</div>
  <p class="title">{html.escape(alert.title)}</p>
  <p class="desc">{html.escape(alert.description)}</p>
</div>
        """,
        unsafe_allow_html=True,
    )

    interrupt = get_interrupt_payload(st.session_state.triage_result or {})

    if interrupt:
        gate = interrupt.get("gate", "unknown")
        st.error(f"HITL pause — Gate: {gate}")
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
        with st.spinner("Running classify → investigate → remediate…"):
            result = _run_async(invoke_triage(initial, thread_id))
        st.session_state.triage_result = result
        if not get_interrupt_payload(result):
            _finish_run(alert, result)
        st.rerun()


def page_playbooks() -> None:
    _section_header(
        "Playbook Library",
        "IR playbooks seeded into SQLite and injected into the Remediate agent.",
    )
    books = load_all_playbooks()
    if not books:
        st.warning("No playbooks loaded. Run `python -m src.seed`.")
        return

    st.caption(f"{len(books)} playbooks · {playbook_count()} DB rows")
    search = st.text_input("Filter", key="pb_search")
    for category, pb in sorted(books.items(), key=lambda x: x[0]):
        blob = f"{category} {pb.get('title', '')} {pb.get('incident_type', '')}".lower()
        if search and search.lower() not in blob:
            continue
        with st.expander(f"{pb.get('title') or category} · {category}"):
            if pb.get("severity"):
                st.caption(f"Severity: {pb['severity']} · Type: {pb.get('incident_type', '')}")
            st.markdown("**Immediate**")
            for step in pb.get("immediate") or []:
                st.write(f"- {step}")
            st.markdown("**Investigation**")
            for step in pb.get("investigation") or []:
                st.write(f"- {step}")
            st.markdown("**Long-term**")
            for step in pb.get("long_term") or []:
                st.write(f"- {step}")


def page_audit() -> None:
    _section_header("Audit Log", "Persisted triage dispositions for this environment.")
    runs = list_triage_runs(limit=100)
    if not runs:
        st.info("No triage runs yet.")
        return

    table = [
        {
            "time": str(r.get("created_at") or "")[:19],
            "status": r.get("status") or "",
            "severity": r.get("severity") or "",
            "title": (r.get("title") or r.get("alert_id") or "")[:70],
            "decision": (r.get("human_decision") or "")[:40],
            "run_id": r.get("run_id") or "",
        }
        for r in runs
    ]
    st.dataframe(table, use_container_width=True, hide_index=True, height=320)

    pick = st.selectbox("Inspect run", [r["run_id"] for r in runs], key="audit_pick")
    detail = get_triage_run(pick)
    if detail:
        cols = st.columns(3)
        with cols[0]:
            st.markdown("**Classification**")
            st.json(detail.get("classification_json") or {})
        with cols[1]:
            st.markdown("**Investigation**")
            st.json(detail.get("investigation_json") or {})
        with cols[2]:
            st.markdown("**Remediation**")
            st.json(detail.get("remediation_json") or {})


def _node(title: str, sub: str = "", kind: str = "") -> str:
    cls = f"dag-node {kind}".strip()
    sub_html = f'<div class="sub">{html.escape(sub)}</div>' if sub else ""
    return (
        f'<div class="{cls}">'
        f'<div class="title">{html.escape(title)}</div>'
        f"{sub_html}"
        f"</div>"
    )


def _arrow(label: str = "") -> str:
    if label:
        return (
            f'<div class="dag-arrow">↓ '
            f'<span class="dag-label">{html.escape(label)}</span></div>'
        )
    return '<div class="dag-arrow">↓</div>'


def page_architecture() -> None:
    st.markdown(
        f"""
<div class="arch-intro">
  <h3>Tech Architecture</h3>
  <p>
    <strong>The problem.</strong> SOC triage is slow and inconsistent when runbooks live in
    wikis, and letting an LLM auto-execute remediation is unsafe. Analysts need speed
    without a blank check on host isolation or credential revocation.
  </p>
  <p>
    <strong>How we solve it.</strong> {html.escape(APP_NAME)} runs a LangGraph pipeline —
    Classify → Investigate → Remediate — grounded in SQLite playbooks. Two
    <em>deterministic</em> HITL gates pause the graph before high-risk steps.
  </p>
  <p>
    <strong>How it’s built.</strong> Streamlit is the analyst console. SQLite holds alerts,
    playbooks, and the audit log (auto-seeded from <code>data/playbooks.json</code> +
    curated scenarios). DeepSeek powers reasoning; <code>OFFLINE_MODE</code> keeps demos free.
  </p>
  <p class="author-line">Author · {html.escape(AUTHOR_NAME)}</p>
</div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="dag-board">
  <h4>End-to-end triage DAG</h4>
  <div class="dag-row">{_node("Alert input", "queue / curated demo", "asphalt")}</div>
  {_arrow()}
  <div class="dag-row">{_node("Classify agent", "severity · category · confidence", "signal")}</div>
  {_arrow()}
  <div class="dag-row">{_node("Investigate agent", "findings · IOCs · scope", "signal")}</div>
  {_arrow("requires_escalation?")}
  <div class="dag-row">
    {_node("HITL Gate #1", "approve / reject", "alert")}
    {_node("Skip gate", "low-risk path", "")}
  </div>
  {_arrow()}
  <div class="dag-row">{_node("Remediate agent", "playbook-guided actions", "signal")}</div>
  {_arrow("CRITICAL/HIGH or approval flag?")}
  <div class="dag-row">
    {_node("HITL Gate #2", "approve / reject", "alert")}
    {_node("auto_resolve", "no interrupt", "")}
  </div>
  {_arrow()}
  <div class="dag-row">
    {_node("execute_and_log", "approved high-risk", "signal")}
    {_node("close_incident", "rejected", "asphalt")}
    {_node("SQLite audit", "triage_runs", "asphalt")}
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    left, right = st.columns(2)
    with left:
        st.markdown(
            f"""
<div class="dag-board">
  <h4>HITL gate rules</h4>
  <div class="dag-row">{_node("Gate #1", "investigation.requires_escalation", "alert")}</div>
  {_arrow()}
  <div class="dag-row">{_node("Gate #2", "CRITICAL/HIGH or requires_human_approval", "alert")}</div>
  {_arrow()}
  <div class="dag-row">{_node("LangGraph interrupt()", "pause until analyst decision", "asphalt")}</div>
</div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f"""
<div class="dag-board">
  <h4>Playbook retrieval</h4>
  <div class="dag-row">{_node("1. SQLite seed", "JSON + embedded", "signal")}</div>
  {_arrow("miss")}
  <div class="dag-row">{_node("2. Qdrant RAG", "optional", "")}</div>
  {_arrow("miss")}
  <div class="dag-row">{_node("3. Embedded dict", "code fallback", "asphalt")}</div>
</div>
            """,
            unsafe_allow_html=True,
        )

    st.caption(
        f"{APP_NAME}: {APP_TAGLINE} · {AUTHOR_NAME} · LangGraph · DeepSeek · SQLite · Streamlit"
    )


def render_console(view: str) -> None:
    if view == "Alert Queue":
        page_alert_queue()
    elif view == "Curated Demos":
        page_curated()
    elif view == "Active Triage":
        page_triage()
    elif view == "Playbooks":
        page_playbooks()
    else:
        page_audit()


def main() -> None:
    inject_styles()
    ensure_session()
    ensure_database()

    # Header on top → tabs below → sidebar (collapsible) for views + DB
    render_header()
    view = render_sidebar()

    tab_console, tab_arch = st.tabs(["Analyst Console", "Tech Architecture"])
    with tab_console:
        render_console(view)
    with tab_arch:
        page_architecture()


if __name__ == "__main__":
    main()
