"""Tests for ingested Hugging Face playbooks in SQLite."""

from src.db import get_playbook_from_db, playbook_count, search_playbooks_db


def test_ingested_playbooks_present():
    assert playbook_count() >= 10


def test_ingested_ransomware_playbook():
    playbook = get_playbook_from_db("malware")
    assert playbook is not None
    assert "Ransomware" in playbook["title"] or "ransomware" in playbook["incident_type"]


def test_ingested_search_ransomware():
    results = search_playbooks_db("ransomware isolate")
    assert len(results) > 0
    assert results[0]["score"] > 0
