"""Idempotent SQLite seed from playbooks.json, embedded playbooks, and curated alerts.

Mirrors the AI Data Agent pattern: ship seed sources in-repo, auto-build the
gitignored .db on first run (Streamlit Cloud / fresh clone).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import db as db_mod
from .db import get_conn, init_db, insert_security_alert, playbook_count, upsert_playbook
from .knowledge_base import PLAYBOOKS
from .paths import default_db_path, playbooks_json_path
from .scenarios import SAMPLE_ALERTS


def _slugify(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_") or "playbook"


def _playbook_key(doc: dict, used: set[str]) -> str:
    """Pick a unique category key; prefer category, else incident_type slug."""
    preferred = (doc.get("category") or "").strip()
    if preferred and preferred not in used:
        return preferred

    incident = (doc.get("incident_type") or doc.get("title") or "playbook").strip()
    key = _slugify(incident)
    if key not in used:
        return key

    base = key
    n = 2
    while f"{base}_{n}" in used:
        n += 1
    return f"{base}_{n}"


def _load_json_playbooks(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list in {path}")
    return data


def seed_playbooks(*, force: bool = False) -> int:
    """Load playbooks.json then overlay embedded PLAYBOOKS (curated wins)."""
    init_db()
    if not force and playbook_count() > 0:
        return playbook_count()

    used: set[str] = set()
    docs: list[dict] = []

    for raw in _load_json_playbooks(playbooks_json_path()):
        key = _playbook_key(raw, used)
        used.add(key)
        docs.append({**raw, "category": key})

    # Embedded playbooks match AlertCategory keys — overwrite on conflict.
    for category, playbook in PLAYBOOKS.items():
        used.add(category)
        docs.append(
            {
                "category": category,
                "title": playbook.get("title", category),
                "incident_type": category.replace("_", " "),
                "severity": "",
                "tactics": "",
                "immediate": playbook.get("immediate", []),
                "investigation": playbook.get("investigation", []),
                "long_term": playbook.get("long_term", []),
                "text": playbook.get("text", ""),
            }
        )

    with get_conn() as conn:
        if force:
            conn.execute("DELETE FROM playbooks")
        for doc in docs:
            upsert_playbook(conn, doc)

    return playbook_count()


def seed_curated_alerts(*, force: bool = False) -> int:
    """Insert curated demo scenarios so Alert Queue works without HF ingest."""
    init_db()
    with get_conn() as conn:
        existing = {
            row[0]
            for row in conn.execute("SELECT event_id FROM alerts").fetchall()
        }
        inserted = 0
        for alert in SAMPLE_ALERTS:
            if not force and alert.alert_id in existing:
                continue
            insert_security_alert(
                conn,
                alert,
                event_type="curated_demo",
                severity="demo",
            )
            inserted += 1
        return inserted


def seed(db_path: Path | None = None, *, force: bool = False) -> Path:
    """Create schema and seed playbooks + curated alerts if empty."""
    target = Path(db_path) if db_path else default_db_path()
    previous = db_mod.DB_PATH
    db_mod.DB_PATH = target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        init_db()
        seed_playbooks(force=force)
        seed_curated_alerts(force=force)
        print(f"Seeded SQLite at {target}")
        print(f"  playbooks: {playbook_count()}")
        with get_conn() as conn:
            alerts = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        print(f"  alerts: {alerts}")
        return target
    finally:
        db_mod.DB_PATH = previous


def database_ready(path: Path | None = None) -> bool:
    """True when DB exists, has playbooks, and at least one alert."""
    target = Path(path) if path else default_db_path()
    if not target.exists() or target.stat().st_size == 0:
        return False

    previous = db_mod.DB_PATH
    db_mod.DB_PATH = target
    try:
        init_db()
        if playbook_count() <= 0:
            return False
        with get_conn() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        return count > 0
    except Exception:
        return False
    finally:
        db_mod.DB_PATH = previous


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed SQLite with playbooks.json + curated demo alerts"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild playbooks and re-insert curated alerts",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Optional SQLite path (default: SQLITE_DB / data/triage.db)",
    )
    args = parser.parse_args()
    seed(args.db, force=args.force)
