"""Tests for SQLite alert storage."""

import tempfile
from pathlib import Path

import pytest

from src import db
from src.models import SecurityAlert
from src.seed import database_ready, seed


@pytest.fixture
def temp_db(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "test.db"
        monkeypatch.setattr(db, "DB_PATH", path)
        db.init_db()
        yield path


def test_siem_row_to_alert():
    row = {
        "event_id": "abc-123",
        "event_type": "ids_alert",
        "source": "Snort v2.9.20",
        "severity": "high",
        "description": "SQL injection attempt blocked",
        "timestamp": "2025-07-11T11:27:00+00:00",
        "alert_type": "SQLi",
        "src_ip": "192.168.1.100",
        "additional_info": "MITRE T1059.001",
    }
    alert = db.siem_row_to_alert(row)
    assert alert.alert_id == "abc-123"
    assert alert.source == "Snort v2.9.20"
    assert "SQLi" in alert.raw_indicators
    assert alert.affected_resource == "192.168.1.100"


def test_insert_and_get_alert(temp_db):
    row = {
        "event_id": "evt-001",
        "event_type": "endpoint",
        "source": "EDR",
        "severity": "critical",
        "description": "Ransomware detected",
        "timestamp": "2025-01-01T00:00:00Z",
        "device_id": "WIN-001",
    }
    with db.get_conn() as conn:
        db.insert_alert(conn, row)

    assert db.alert_count() == 1
    alert = db.get_alert("evt-001")
    assert alert is not None
    assert alert.title == "endpoint alert"
    assert alert.affected_resource == "WIN-001"


def test_list_alerts_filter(temp_db):
    rows = [
        {
            "event_id": "a1",
            "event_type": "firewall",
            "source": "FW",
            "severity": "low",
            "description": "blocked scan",
            "timestamp": "2025-01-01",
        },
        {
            "event_id": "a2",
            "event_type": "ids_alert",
            "source": "IDS",
            "severity": "high",
            "description": "exploit attempt",
            "timestamp": "2025-01-02",
        },
    ]
    with db.get_conn() as conn:
        for row in rows:
            db.insert_alert(conn, row)

    high = db.list_alerts(severity="high")
    assert len(high) == 1
    assert high[0]["event_id"] == "a2"


def test_save_triage_run(temp_db):
    with db.get_conn() as conn:
        db.insert_alert(
            conn,
            {
                "event_id": "a1",
                "event_type": "auth",
                "source": "SIEM",
                "severity": "medium",
                "description": "test",
                "timestamp": "2025-01-01",
            },
        )

    db.save_triage_run(
        run_id="run-1",
        thread_id="thread-1",
        alert_id="a1",
        status="executed",
        human_decision="approved",
        classification=None,
        investigation=None,
        remediation=None,
    )
    runs = db.list_triage_runs()
    assert len(runs) == 1
    detail = db.get_triage_run("run-1")
    assert detail["status"] == "executed"


def test_insert_security_alert(temp_db):
    alert = SecurityAlert(
        alert_id="ALT-TEST-1",
        source="UnitTest",
        title="Test alert",
        description="Seed path for curated scenarios",
        raw_indicators=["ioc=1"],
        affected_resource="host-1",
        timestamp="2026-01-01T00:00:00Z",
    )
    with db.get_conn() as conn:
        db.insert_security_alert(conn, alert, event_type="curated_demo", severity="demo")

    loaded = db.get_alert("ALT-TEST-1")
    assert loaded is not None
    assert loaded.title == "Test alert"
    stats = db.db_stats()
    assert stats["alerts"] == 1


def test_seed_creates_playbooks_and_curated_alerts(monkeypatch, tmp_path):
    path = tmp_path / "seeded.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    assert not database_ready(path)

    seed(path)
    assert database_ready(path)
    assert db.playbook_count() >= 8
    assert db.alert_count() >= 6
    assert db.get_alert("ALT-2026-0847") is not None
    assert db.get_playbook_from_db("malware") is not None

