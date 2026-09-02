"""SQLite storage for SIEM alerts and triage audit log."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .models import SecurityAlert

load_dotenv()

DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DB_PATH = Path(os.getenv("SQLITE_DB", DATA_DIR / "triage.db"))


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_conn():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                event_id TEXT PRIMARY KEY,
                event_type TEXT,
                source TEXT,
                severity TEXT,
                description TEXT,
                timestamp TEXT,
                title TEXT,
                affected_resource TEXT,
                raw_indicators TEXT,
                raw_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_event_type ON alerts(event_type);

            CREATE TABLE IF NOT EXISTS triage_runs (
                run_id TEXT PRIMARY KEY,
                thread_id TEXT,
                alert_id TEXT,
                status TEXT,
                human_decision TEXT,
                classification_json TEXT,
                investigation_json TEXT,
                remediation_json TEXT,
                created_at TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_runs_alert ON triage_runs(alert_id);
            CREATE INDEX IF NOT EXISTS idx_runs_created ON triage_runs(created_at);

            CREATE TABLE IF NOT EXISTS playbooks (
                category TEXT PRIMARY KEY,
                title TEXT,
                incident_type TEXT,
                severity TEXT,
                tactics TEXT,
                immediate TEXT,
                investigation TEXT,
                long_term TEXT,
                body_text TEXT
            );
            """
        )


def siem_row_to_alert(row: dict[str, Any]) -> SecurityAlert:
    """Map Advanced_SIEM_Dataset row to SecurityAlert."""
    indicators: list[str] = []
    for key in ("additional_info", "alert_type", "signature_id", "category"):
        val = row.get(key)
        if val:
            indicators.append(str(val))
    meta = row.get("advanced_metadata") or {}
    if isinstance(meta, dict):
        if meta.get("risk_score") is not None:
            indicators.append(f"risk_score={meta['risk_score']}")
        if meta.get("geo_location"):
            indicators.append(f"geo={meta['geo_location']}")

    for key in ("src_ip", "dst_ip", "user", "device_id"):
        val = row.get(key)
        if val:
            indicators.append(f"{key}={val}")

    resource = (
        row.get("resource_id")
        or row.get("device_id")
        or row.get("src_ip")
        or row.get("dst_ip")
        or row.get("user")
        or ""
    )
    title = row.get("alert_type") or f"{row.get('event_type', 'siem')} alert"

    return SecurityAlert(
        alert_id=str(row["event_id"]),
        source=str(row.get("source", "SIEM")),
        title=str(title),
        description=str(row.get("description", "")),
        raw_indicators=indicators,
        affected_resource=str(resource),
        timestamp=str(row.get("timestamp", "")),
    )


def insert_alert(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    alert = siem_row_to_alert(row)
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts
        (event_id, event_type, source, severity, description, timestamp,
         title, affected_resource, raw_indicators, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            str(row.get("event_type", "")),
            alert.source,
            str(row.get("severity", "")),
            alert.description,
            alert.timestamp,
            alert.title,
            alert.affected_resource,
            json.dumps(alert.raw_indicators),
            json.dumps(row, default=str),
        ),
    )


def alert_count() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
        return int(row["c"])


def list_alerts(
    *,
    severity: str | None = None,
    event_type: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if severity and severity != "all":
        clauses.append("severity = ?")
        params.append(severity)
    if event_type and event_type != "all":
        clauses.append("event_type = ?")
        params.append(event_type)
    if search:
        clauses.append("(description LIKE ? OR title LIKE ? OR event_id LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT event_id, event_type, source, severity, description, timestamp, title
        FROM alerts {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_alert(event_id: str) -> SecurityAlert | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE event_id = ?", (event_id,)
        ).fetchone()
        if not row:
            return None
        indicators = json.loads(row["raw_indicators"] or "[]")
        return SecurityAlert(
            alert_id=row["event_id"],
            source=row["source"],
            title=row["title"],
            description=row["description"],
            raw_indicators=indicators,
            affected_resource=row["affected_resource"] or "",
            timestamp=row["timestamp"] or "",
        )


def distinct_values(column: str) -> list[str]:
    if column not in ("severity", "event_type"):
        return []
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT {column} FROM alerts WHERE {column} IS NOT NULL ORDER BY 1"
        ).fetchall()
        return [r[0] for r in rows if r[0]]


def save_triage_run(
    *,
    run_id: str,
    thread_id: str,
    alert_id: str,
    status: str,
    human_decision: str,
    classification: Any | None,
    investigation: Any | None,
    remediation: Any | None,
) -> None:
    def _dump(obj: Any) -> str | None:
        if obj is None:
            return None
        if hasattr(obj, "model_dump"):
            return json.dumps(obj.model_dump(), default=str)
        return json.dumps(obj, default=str)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO triage_runs
            (run_id, thread_id, alert_id, status, human_decision,
             classification_json, investigation_json, remediation_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                thread_id,
                alert_id,
                status,
                human_decision,
                _dump(classification),
                _dump(investigation),
                _dump(remediation),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def list_triage_runs(limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT r.run_id, r.alert_id, r.status, r.human_decision, r.created_at,
                   a.title, a.severity, a.event_type
            FROM triage_runs r
            LEFT JOIN alerts a ON a.event_id = r.alert_id
            ORDER BY r.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_triage_run(run_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM triage_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        for key in ("classification_json", "investigation_json", "remediation_json"):
            if data.get(key):
                data[key] = json.loads(data[key])
        return data


def _row_to_playbook_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "title": row["title"],
        "immediate": json.loads(row["immediate"] or "[]"),
        "investigation": json.loads(row["investigation"] or "[]"),
        "long_term": json.loads(row["long_term"] or "[]"),
        "incident_type": row["incident_type"] or "",
        "severity": row["severity"] or "",
        "tactics": row["tactics"] or "",
        "text": row["body_text"] or "",
    }


def upsert_playbook(conn: sqlite3.Connection, doc: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO playbooks
        (category, title, incident_type, severity, tactics, immediate,
         investigation, long_term, body_text)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            doc["category"],
            doc.get("title", ""),
            doc.get("incident_type", ""),
            doc.get("severity", ""),
            doc.get("tactics", ""),
            json.dumps(doc.get("immediate", [])),
            json.dumps(doc.get("investigation", [])),
            json.dumps(doc.get("long_term", [])),
            doc.get("text", ""),
        ),
    )


def playbook_count() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM playbooks").fetchone()
        return int(row["c"])


def get_playbook_from_db(category: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM playbooks WHERE category = ?", (category,)
        ).fetchone()
        if row:
            return _row_to_playbook_dict(row)
        row = conn.execute(
            "SELECT * FROM playbooks WHERE incident_type LIKE ? LIMIT 1",
            (f"%{category.replace('_', ' ')}%",),
        ).fetchone()
        if row:
            return _row_to_playbook_dict(row)
        return None


def search_playbooks_db(query: str, top_k: int = 3) -> list[dict[str, Any]]:
    if not query.strip():
        return []
    query_lower = query.lower()
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM playbooks").fetchall()

    results = []
    for row in rows:
        playbook = _row_to_playbook_dict(row)
        text = (
            f"{row['category']} {row['title']} {row['body_text']} "
            f"{row['incident_type']}"
        ).lower()
        score = sum(1 for word in query_lower.split() if word in text)
        if score > 0:
            results.append(
                {
                    "category": row["category"],
                    "playbook": playbook,
                    "score": score,
                }
            )
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]


def load_all_playbooks() -> dict[str, dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM playbooks").fetchall()
    return {row["category"]: _row_to_playbook_dict(row) for row in rows}
